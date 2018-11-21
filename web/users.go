package web

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/notion/bastion/config"
	"github.com/notion/bastion/ssh"
	cryptossh "golang.org/x/crypto/ssh"
)

func user(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})
		var users []config.User

		env.DB.Find(&users)

		retData["status"] = "ok"
		retData["users"] = users

		c.JSON(http.StatusOK, retData)
	}
}

func updateUser(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		id, _ := c.Params.Get("id")
		retData := make(map[string]interface{})
		var user config.User

		env.DB.Find(&user, id)

		user.Email = c.PostForm("email")
		user.Authorized = c.PostForm("authorized") == "on"
		user.Admin = c.PostForm("admin") == "on"
		user.AuthorizedHosts = c.PostForm("authorizedhosts")
		user.UnixUser = c.PostForm("unixuser")

		if user.Authorized && user.Cert == nil || c.Query("override") == "on" {
			if signer == nil {
				signer = ssh.ParsePrivateKey(env.Config.UserPrivateKey, env.PKPassphrase, env)
			}

			if casigner == nil {
				duration, err := time.ParseDuration(env.Config.Expires)
				if err != nil {
					env.Red.Println("Unable to parse duration to expire:", err)
				}

				casigner = ssh.NewCASigner(signer, duration, []string{}, []string{})
			}

			cert, PK, err := casigner.Sign(env, user.Email, nil)
			if err != nil {
				env.Red.Println("Unable to sign PrivateKey:", err)
			}

			marshaled := cryptossh.MarshalAuthorizedKey(cert)

			user.Cert = marshaled
			user.CertExpires = time.Unix(int64(cert.ValidBefore), 0)
			user.PrivateKey = PK
		}

		env.DB.Save(&user)

		retData["status"] = "ok"
		retData["user"] = user

		c.JSON(http.StatusOK, retData)
	}
}

func downloadKey(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		sessionUser := session.Get("user").(*config.User)

		id, _ := c.Params.Get("id")
		var user config.User

		if env.DB.Find(&user, id).RecordNotFound() || user.Cert == nil || (!sessionUser.Admin && sessionUser.ID != user.ID) {
			http.Redirect(c.Writer, c.Request, "/users", http.StatusFound)
			return
		}

		if user.Authorized {
			if signer == nil {
				signer = ssh.ParsePrivateKey(env.Config.UserPrivateKey, env.PKPassphrase, env)
			}

			if casigner == nil {
				duration, err := time.ParseDuration(env.Config.Expires)
				if err != nil {
					env.Red.Println("Unable to parse duration to expire:", err)
				}

				casigner = ssh.NewCASigner(signer, duration, []string{}, []string{})
			}

			gracePeriod, err := time.ParseDuration(env.Vconfig.GetString("sshcert.graceperiod"))
			if err != nil {
				env.Red.Println("Unable to parse duration to expire:", err)
			}

			if user.Cert != nil && user.CertExpires.Before(time.Now().Add(gracePeriod)) {
				cert, PK, err := casigner.Sign(env, user.Email, nil)
				if err != nil {
					env.Red.Println("Unable to sign PrivateKey:", err)
				}

				marshaled := cryptossh.MarshalAuthorizedKey(cert)

				user.Cert = marshaled
				user.CertExpires = time.Unix(int64(cert.ValidBefore), 0)
				user.PrivateKey = PK

				env.DB.Save(&user)
			}
		}

		buf := new(bytes.Buffer)
		writer := zip.NewWriter(buf)

		for _, v := range []string{"id_rsa", "id_rsa.pub", "id_rsa-cert.pub"} {
			var fileData []byte
			switch v {
			case "id_rsa":
				fileData = user.PrivateKey
				break
			case "id_rsa.pub":
				pk := ssh.ParsePrivateKey(user.PrivateKey, "", env)
				fileData = cryptossh.MarshalAuthorizedKey(pk.PublicKey())
				break
			case "id_rsa-cert.pub":
				fileData = user.Cert
				break
			}

			fileHeader := &zip.FileHeader{
				Name:               v,
				UncompressedSize64: uint64(len(fileData)),
				Modified:           time.Now(),
				Method:             zip.Deflate,
			}

			fileHeader.SetMode(0600)

			fileWriter, err := writer.CreateHeader(fileHeader)
			if err != nil {
				env.Red.Println("Unable to write file to zip:", err)
			}

			fileWriter.Write(fileData)
		}

		writer.Close()

		c.Header("Content-Type", "application/zip")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"authorization.zip\""))
		c.Writer.Write(buf.Bytes())
	}
}

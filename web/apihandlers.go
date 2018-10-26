package web

import "C"
import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	"github.com/notion/trove_ssh_bastion/config"
	"github.com/notion/trove_ssh_bastion/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

var signer cryptossh.Signer
var casigner *ssh.CASigner

func index(env *config.Env, conf oauth2.Config) func(c *gin.Context) {
	return func(c *gin.Context) {
		code := c.Query("code")
		session := sessions.Default(c)

		if code == "" {
			if loggedIn := session.Get("loggedin"); loggedIn != nil {
				if loggedIn.(bool) {
					http.Redirect(c.Writer, c.Request, "/sessions", http.StatusFound)
					return
				}
			}

			state := sha256.Sum256(securecookie.GenerateRandomKey(32))

			session.Set("state", base64.URLEncoding.EncodeToString(state[:]))
			session.Save()

			c.Redirect(http.StatusFound, conf.AuthCodeURL(session.Get("state").(string)))
			return
		} else {
			if c.Query("state") == session.Get("state") {
				token, err := conf.Exchange(context.TODO(), code)
				if err != nil {
					env.Red.Println("ISSUE EXCHANGING CODE:", err)
				}

				client := conf.Client(context.TODO(), token)

				resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
				if err != nil {
					env.Red.Println("ERROR GETTING USER INFO", err)
				}
				defer resp.Body.Close()

				userData := make(map[string]interface{})

				data, _ := ioutil.ReadAll(resp.Body)

				err = json.Unmarshal(data, &userData)
				if err != nil {
					env.Red.Println("Unable to unmarshal user info from google", err)
				}

				var user config.User
				var userCount int

				env.DB.Table("users").Count(&userCount)
				env.DB.First(&user, "email = ?", userData["email"].(string))

				if userCount == 0 {
					user.Admin = true
				}

				user.Email = userData["email"].(string)
				user.AuthToken = token.AccessToken

				if user.AuthorizedHosts == "" {
					user.AuthorizedHosts = env.Config.DefaultHosts
				}

				env.DB.Save(&user)

				if user.Cert != nil {
					user.Cert = []byte{}
					user.PrivateKey = []byte{}
				}

				session.Set("user", user)
				session.Set("loggedin", true)
				session.Save()

				c.Redirect(http.StatusFound, "/sessions")
				return
			} else {
				c.Redirect(http.StatusFound, "/")
				return
			}
		}
	}
}

func logout(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		session.Clear()
		session.Save()

		c.Redirect(http.StatusFound, "/")
		return
	}
}

func session(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		var sessions []config.Session
		env.DB.Preload("User", func(db *gorm.DB) *gorm.DB {
			return db.Select([]string{"id", "email"})
		}).Select([]string{"user_id", "time", "name", "host", "hostname", "users", "command"}).Find(&sessions)

		retData := make(map[string]interface{})

		retData["status"] = "ok"
		retData["sessions"] = sessions

		c.JSON(http.StatusOK, retData)
	}
}

func sessionId(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		id, _ := c.Params.Get("id")
		ctx := context.Background()

		reader, err := env.LogsBucket.Object(id).ReadCompressed(true).NewReader(ctx)
		if err != nil {
			c.Writer.WriteHeader(http.StatusNotFound)
		} else {
			c.Header("Content-Encoding", "gzip")
			c.Header("Transfer-Encoding", "gzip")
			c.Writer.WriteHeader(http.StatusOK)
			io.Copy(c.Writer, reader)
		}
	}
}

func liveSession(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})

		var newSessions []interface{}
		env.SshProxyClients.Range(func(key interface{}, value interface{}) bool {
			client := value.(*config.SshProxyClient)

			client.Mutex.Lock()
			if client.SshServerClient.User != nil && len(client.SshShellSessions) > 0 {
				sessionData := make(map[string]interface{})
				sessionData["Name"] = key.(string)
				sessionData["Host"] = client.SshServerClient.ProxyTo
				sessionData["Hostname"] = client.SshServerClient.ProxyToHostname
				sessionData["User"] = client.SshServerClient.User.Email
				sessionData["Sessions"] = len(client.SshShellSessions)
				wholeCommand := ""

				for _, v := range client.SshShellSessions {
					for _, r := range v.Reqs {
						if r.ReqType == "shell" || r.ReqType == "exec" {
							command := ""
							if string(r.ReqData) == "" {
								command = "Main Shell"
							} else {
								command = string(r.ReqData)
							}

							wholeCommand += command + ", "
							break
						}
					}
				}
				sessionData["Command"] = wholeCommand
				newSessions = append(newSessions, sessionData)
			}
			client.Mutex.Unlock()

			return true
		})

		retData["status"] = "ok"
		retData["livesessions"] = newSessions

		c.JSON(http.StatusOK, retData)
	}
}

func openSessions(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})

		var newSessions []interface{}
		env.SshProxyClients.Range(func(key interface{}, value interface{}) bool {
			client := value.(*config.SshProxyClient)

			sessionData := make(map[string]interface{})
			allChans := make([]map[string]interface{}, 0)
			sessionData["name"] = key.(string)

			for _, v2 := range client.SshChans {
				chanData := make(map[string]interface{})
				chanData["reqs"] = v2.Reqs
				chanData["data"] = v2.ChannelData
				chanData["type"] = v2.ChannelType
				allChans = append(allChans, chanData)
			}

			sessionData["chans"] = allChans

			newSessions = append(newSessions, sessionData)

			return true
		})

		retData["status"] = "ok"
		retData["livesessions"] = newSessions

		c.JSON(http.StatusOK, retData)
	}
}

func disconnectLiveSession(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})

		pathKey, ok := c.Params.Get("id")
		if !ok {
			returnErr(c.Writer, c.Request, errors.New("can't find id"), http.StatusInternalServerError)
			return
		}
		sidKey, ok := c.Params.Get("sid")
		if !ok {
			sidKey = ""
		}

		if proxyClientInterface, ok := env.SshProxyClients.Load(pathKey); ok {
			proxyClient := proxyClientInterface.(*config.SshProxyClient)
			place := 0
			var err error
			if sidKey != "" {
				place, err = strconv.Atoi(sidKey)
				if err != nil {
					returnErr(c.Writer, c.Request, err, http.StatusInternalServerError)
				}
			}

			if place < len(proxyClient.SshShellSessions) {
				proxyClient.Mutex.Lock()
				chanInfo := proxyClient.SshShellSessions[place]
				proxyClient.Mutex.Unlock()

				proxyChan := *chanInfo.ProxyChan
				proxyChan.Close()
			} else {
				returnErr(c.Writer, c.Request, errors.New("can't find id"), http.StatusInternalServerError)
			}
		} else {
			returnErr(c.Writer, c.Request, errors.New("can't find client"), http.StatusInternalServerError)
		}

		retData["status"] = "ok"

		c.JSON(http.StatusOK, retData)
	}
}

func liveSessionWS(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		pathKey, ok := c.Params.Get("id")
		if !ok {
			returnErr(c.Writer, c.Request, errors.New("can't find id"), http.StatusInternalServerError)
			return
		}
		sidKey, ok := c.Params.Get("sid")
		if !ok {
			sidKey = ""
		}

		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)

		env.Blue.Println("New WebSocket Connection From:", c.Request.RemoteAddr)
		env.Blue.Println("Path:", pathKey, sidKey)

		if err != nil {
			env.Red.Println("Upgrade error:", err)
			return
		}

		if proxyClientInterface, ok := env.SshProxyClients.Load(pathKey); ok {
			proxyClient := proxyClientInterface.(*config.SshProxyClient)
			place := 0
			if sidKey != "" {
				place, err = strconv.Atoi(sidKey)
			}

			if place < len(proxyClient.SshShellSessions) {
				clientMapInterface, _ := env.WebsocketClients.LoadOrStore(pathKey+sidKey, make(map[string]*config.WsClient))

				proxyClient.Mutex.Lock()
				clientMap := clientMapInterface.(map[string]*config.WsClient)

				chanInfo := proxyClient.SshShellSessions[place]

				clientMap[conn.RemoteAddr().String()] = &config.WsClient{
					Client: conn,
				}

				wsWriter, err := conn.NextWriter(websocket.TextMessage)
				if err != nil {
					env.Red.Println("Error establishing ws writer in playback")
				}

				for _, frame := range chanInfo.Closer.Cast.Frames {
					wsWriter.Write([]byte(frame.Data))
				}

				wsWriter.Close()
				proxyClient.Mutex.Unlock()
			} else {
				return
			}

		} else {
			return
		}

		for {
			_, p, err := conn.ReadMessage()
			if err != nil {
				env.Red.Println("wsReader error:", err)
				break
			}

			if proxyClientInterface, ok := env.SshProxyClients.Load(pathKey); ok {
				proxyClient := proxyClientInterface.(*config.SshProxyClient)
				place := 0
				if sidKey != "" {
					place, err = strconv.Atoi(sidKey)
				}

				if place < len(proxyClient.SshShellSessions) {
					sshProxyClient := *proxyClient.SshShellSessions[place].ProxyChan

					if sshProxyClient != nil {
						proxyClient.SshShellSessions[place].Closer.Mutex.Lock()
						proxyClient.SshShellSessions[place].Closer.CurrentUser = userData.Email
						proxyClient.SshShellSessions[place].Closer.Mutex.Unlock()
						_, err = sshProxyClient.Write(p)

						if err != nil {
							env.Red.Println("SSH Session Write Error:", err)
							break
						}
					}
				} else {
					return
				}
			}
		}

		defer func() {
			conn.Close()
			clientInterface, _ := env.WebsocketClients.Load(pathKey + sidKey)
			client := clientInterface.(map[string]*config.WsClient)
			delete(client, conn.RemoteAddr().String())

			env.Magenta.Println("Closed WebSocket Connection From:", c.Request.RemoteAddr)
		}()
	}
}

func user(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})
		var users []config.User

		env.DB.Find(&users)

		retData["status"] = "ok"
		retData["users"] = users

		returnJson(c.Writer, c.Request, retData, 0)
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

			if user.Cert != nil && user.CertExpires.Before(time.Now()) {
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

package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"

	"github.com/notion/bastion/iap"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/notion/bastion/config"
	"github.com/notion/bastion/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

var (
	signer   cryptossh.Signer
	casigner *ssh.CASigner
)

func index(env *config.Env, conf oauth2.Config) func(c *gin.Context) {
	return func(c *gin.Context) {
		if env.Vconfig.GetBool("gce.iap.enabled") {
			indexIAP(env, conf)(c)
			return
		}

		session := sessions.Default(c)

		code := c.Query("code")

		if code == "" {
			if loggedIn := session.Get("loggedin"); loggedIn != nil {
				if loggedIn.(bool) {
					http.Redirect(c.Writer, c.Request, "/authenticated", http.StatusFound)
					return
				}
			}

			state := sha256.Sum256(securecookie.GenerateRandomKey(32))

			session.Set("state", base64.URLEncoding.EncodeToString(state[:]))
			session.Save()

			c.Redirect(http.StatusFound, conf.AuthCodeURL(session.Get("state").(string)))
			c.Abort()
			return
		}

		if c.Query("state") == session.Get("state") {
			token, err := conf.Exchange(context.TODO(), code)
			if err != nil {
				env.Red.Println("ISSUE EXCHANGING CODE:", err)
			}

			userData, err := getUserData(conf, token)
			if err != nil {
				env.Red.Println("ISSUE GETTING USER DATA:", err)
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
			session.Set("otpauthed", false)
			session.Save()

			if env.Vconfig.GetBool("otp.enabled") {
				c.Redirect(http.StatusFound, "/otp")
				c.Abort()
				return
			}
		}

		c.Redirect(http.StatusFound, "/")
		c.Abort()
		return
	}
}

func indexIAP(env *config.Env, conf oauth2.Config) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		if c.GetHeader("x-goog-iap-jwt-assertion") != "" {
			iap := iap.NewIAPVerifier(env.Vconfig.GetString("gce.iap.aud"), env.Vconfig.GetString("gce.iap.issuer"), env.Vconfig.GetStringSlice("gce.iap.hd"))
			verified, claims, err := iap.Verify(c.GetHeader("x-goog-iap-jwt-assertion"))
			if err == nil && verified {
				var user config.User
				var userCount int

				env.DB.Table("users").Count(&userCount)
				env.DB.First(&user, "email = ?", claims["email"].(string))

				if userCount == 0 {
					user.Admin = true
				}

				user.Email = claims["email"].(string)

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
				session.Set("otpauthed", false)
				session.Save()

				if env.Vconfig.GetBool("otp.enabled") {
					c.Redirect(http.StatusFound, "/otp")
					c.Abort()
					return
				}

				c.Redirect(http.StatusFound, "/")
				c.Abort()
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{"status": false})
		return
	}
}

func Logout(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		session.Clear()
		session.Save()

		c.Redirect(http.StatusFound, "/")
		c.Abort()
		return
	}
}

func openSessions(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})

		var newSessions []interface{}
		env.SSHProxyClients.Range(func(key interface{}, value interface{}) bool {
			client := value.(*config.SSHProxyClient)

			sessionData := make(map[string]interface{})
			allChans := make([]map[string]interface{}, 0)
			sessionData["name"] = key.(string)

			for _, v2 := range client.SSHChans {
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

		var newClientSessions []interface{}
		env.SSHServerClients.Range(func(key interface{}, value interface{}) bool {
			client := value.(*config.SSHServerClient)

			sessionData := make(map[string]interface{})

			sessionData["client"] = client.Client.RemoteAddr()
			sessionData["proxyto"] = client.ProxyTo
			sessionData["proxytohostname"] = client.ProxyToHostname

			newClientSessions = append(newClientSessions, sessionData)

			return true
		})

		retData["status"] = "ok"
		retData["livesessions"] = newSessions
		retData["livesessions2"] = newClientSessions

		c.JSON(http.StatusOK, retData)
	}
}

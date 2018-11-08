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
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/koding/websocketproxy"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	"github.com/notion/bastion/config"
	"github.com/notion/bastion/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

var (
	signer      cryptossh.Signer
	casigner    *ssh.CASigner
	keys        = make(map[string]string)
	keyLoadTime time.Time
)

func index(env *config.Env, conf oauth2.Config) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		if env.GCE {
			if int(time.Now().Sub(keyLoadTime).Seconds()) > 60 {
				keyLoadTime = time.Now()

				resp, err := http.Get("https://www.gstatic.com/iap/verify/public_key")
				if err != nil {
					env.Red.Println(err)
				}
				defer resp.Body.Close()

				body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					env.Red.Println(err)
				}

				err = json.Unmarshal(body, &keys)
				if err != nil {
					env.Red.Println(err)
				}
			}

			if c.GetHeader("x-goog-iap-jwt-assertion") != "" {
				token, err := jwt.Parse(c.GetHeader("x-goog-iap-jwt-assertion"), func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
						return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
					}

					key, err := jwt.ParseECPublicKeyFromPEM([]byte(keys[token.Header["kid"].(string)]))
					if err != nil {
						env.Red.Println(err)
					}

					return key, nil
				})
				if err != nil {
					env.Red.Println(err)
				}

				if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
					if claims.VerifyAudience(env.Vconfig.GetString("gce.iap.aud"), true) && claims.VerifyIssuer(env.Vconfig.GetString("gce.iap.issuer"), true) {
						if hd, ok := claims["hd"].(string); ok {
							for _, v := range env.Vconfig.GetStringSlice("gce.iap.hd") {
								if v == hd {
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
									session.Save()

									c.Redirect(http.StatusFound, "/sessions")
									return
								}
							}
						}
					}
				} else {
					env.Red.Println(err)
				}
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{"status": false})
			return
		}

		code := c.Query("code")

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
		}

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
		}

		c.Redirect(http.StatusFound, "/")
		return
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

func sessionID(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		id, _ := c.Params.Get("id")
		ctx := context.Background()

		reader, err := env.LogsBucket.Object(id).ReadCompressed(true).NewReader(ctx)
		if err != nil {
			c.Writer.WriteHeader(http.StatusNotFound)
		} else {
			c.Header("Content-Encoding", "gzip")

			if !env.GCE {
				c.Header("Transfer-Encoding", "gzip")
			}

			c.Writer.WriteHeader(http.StatusOK)
			io.Copy(c.Writer, reader)
		}
	}
}

func liveSession(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})

		if env.GCE {
			var livesessions []config.LiveSession
			env.DB.Preload("User", func(db *gorm.DB) *gorm.DB {
				return db.Select([]string{"id", "email"})
			}).Select([]string{"user_id", "time", "name", "host", "hostname", "ws", "command"}).Find(&livesessions)

			sessions := make(map[string]int)
			for _, v := range livesessions {
				if _, ok := sessions[v.Name]; ok {
					sessions[v.Name]++
				} else {
					sessions[v.Name] = 1
				}
			}

			var newSessions []interface{}
			for _, v := range livesessions {
				newSessions = append(newSessions, map[string]interface{}{
					"Name":     v.Name,
					"WS":       v.WS,
					"Host":     v.Host,
					"Hostname": v.Hostname,
					"User":     v.User.Email,
					"Sessions": sessions[v.Name],
					"Command":  v.Command,
				})
			}

			retData := make(map[string]interface{})

			retData["status"] = "ok"
			retData["livesessions"] = newSessions

			c.JSON(http.StatusOK, retData)
			return
		}

		var newSessions []interface{}
		env.SSHProxyClients.Range(func(key interface{}, value interface{}) bool {
			client := value.(*config.SSHProxyClient)
			serverClient := client.SSHServerClient

			client.Mutex.Lock()
			if client.SSHServerClient.User != nil && len(client.SSHShellSessions) > 0 {
				sessionData := make(map[string]interface{})
				sessionData["Name"] = serverClient.Client.RemoteAddr().String()
				sessionData["WS"] = key.(string)
				sessionData["Host"] = client.SSHServerClient.ProxyTo
				sessionData["Hostname"] = client.SSHServerClient.ProxyToHostname
				sessionData["User"] = client.SSHServerClient.User.Email
				sessionData["Sessions"] = len(client.SSHShellSessions)
				wholeCommand := ""

				for _, v := range client.SSHShellSessions {
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

func disconnectLiveSession(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})

		pathKey, ok := c.Params.Get("id")
		if !ok {
			c.AbortWithError(http.StatusInternalServerError, errors.New("can't find id"))
			return
		}
		sidKey, ok := c.Params.Get("sid")
		if !ok {
			sidKey = ""
		}

		authcode := c.Query("authcode")

		if env.GCE {
			var dblivesession config.LiveSession
			env.DB.First(&dblivesession, "WS = ?", pathKey)
			if authcode == "" {
				newURL := c.Request.URL
				newURL.Scheme = "http"
				newURL.Host = dblivesession.Bastion
				newURL.RawQuery = fmt.Sprintf("authcode=%s", dblivesession.AuthCode)

				rProxy := &httputil.ReverseProxy{
					Director: func(req *http.Request) {
						req.URL = newURL
					},
				}
				rProxy.ServeHTTP(c.Writer, c.Request)
				return
			}

			if authcode != dblivesession.AuthCode {
				c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{"status": false, "error": "Invalid auth code."})
			}
		}

		if proxyClientInterface, ok := env.SSHProxyClients.Load(pathKey); ok {
			proxyClient := proxyClientInterface.(*config.SSHProxyClient)
			place := 0
			var err error
			if sidKey != "" {
				place, err = strconv.Atoi(sidKey)
				if err != nil {
					c.AbortWithError(http.StatusInternalServerError, err)
				}
			}

			if place < len(proxyClient.SSHShellSessions) {
				proxyClient.Mutex.Lock()
				chanInfo := proxyClient.SSHShellSessions[place]
				proxyClient.Mutex.Unlock()

				proxyChan := *chanInfo.ProxyChan
				proxyChan.Close()
			} else {
				c.AbortWithError(http.StatusInternalServerError, errors.New("can't find id"))
			}
		} else {
			c.AbortWithError(http.StatusInternalServerError, errors.New("can't find client"))
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
			c.AbortWithError(http.StatusInternalServerError, errors.New("can't find id"))
			return
		}
		sidKey, ok := c.Params.Get("sid")
		if !ok {
			sidKey = ""
		}

		authcode := c.Query("authcode")

		if env.GCE {
			var dblivesession config.LiveSession
			env.DB.First(&dblivesession, "WS = ?", pathKey)
			if authcode == "" {
				newURL := c.Request.URL
				newURL.Scheme = "ws"
				newURL.Host = dblivesession.Bastion
				newURL.RawQuery = fmt.Sprintf("authcode=%s", dblivesession.AuthCode)

				WSProxy := websocketproxy.NewProxy(newURL)
				WSProxy.ServeHTTP(c.Writer, c.Request)
				return
			}

			if authcode != dblivesession.AuthCode {
				c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{"status": false, "error": "Invalid auth code."})
			}
		}

		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)

		env.Blue.Println("New WebSocket Connection From:", c.Request.RemoteAddr)
		env.Blue.Println("Path:", pathKey, sidKey)

		if err != nil {
			env.Red.Println("Upgrade error:", err)
			return
		}

		if proxyClientInterface, ok := env.SSHProxyClients.Load(pathKey); ok {
			proxyClient := proxyClientInterface.(*config.SSHProxyClient)
			place := 0
			if sidKey != "" {
				place, err = strconv.Atoi(sidKey)
			}

			if place < len(proxyClient.SSHShellSessions) {
				clientMapInterface, _ := env.WebsocketClients.LoadOrStore(pathKey+sidKey, make(map[string]*config.WsClient))

				proxyClient.Mutex.Lock()
				clientMap := clientMapInterface.(map[string]*config.WsClient)

				chanInfo := proxyClient.SSHShellSessions[place]

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

			if proxyClientInterface, ok := env.SSHProxyClients.Load(pathKey); ok {
				proxyClient := proxyClientInterface.(*config.SSHProxyClient)
				place := 0
				if sidKey != "" {
					place, err = strconv.Atoi(sidKey)
				}

				if place < len(proxyClient.SSHShellSessions) {
					SSHProxyClient := *proxyClient.SSHShellSessions[place].ProxyChan

					if SSHProxyClient != nil {
						proxyClient.SSHShellSessions[place].Closer.Mutex.Lock()
						proxyClient.SSHShellSessions[place].Closer.CurrentUser = userData.Email
						proxyClient.SSHShellSessions[place].Closer.Mutex.Unlock()
						_, err = SSHProxyClient.Write(p)

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

package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
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
	otp "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
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
									session.Set("otpauthed", false)
									session.Save()

									if env.Vconfig.GetBool("otp.enabled") {
										c.Redirect(http.StatusFound, "/otp")
										c.Abort()
										return
									}

									c.Redirect(http.StatusFound, "/sessions")
									c.Abort()
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
			c.Abort()
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
			session.Set("otpauthed", false)
			session.Save()

			if env.Vconfig.GetBool("otp.enabled") {
				c.Redirect(http.StatusFound, "/otp")
				c.Abort()
				return
			}

			c.Redirect(http.StatusFound, "/sessions")
			c.Abort()
			return
		}

		c.Redirect(http.StatusFound, "/")
		c.Abort()
		return
	}
}

func logout(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		session.Clear()
		session.Save()

		c.Redirect(http.StatusFound, "/")
		c.Abort()
		return
	}
}

func session(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		limit, err := strconv.Atoi(c.Query("length"))
		if err != nil {
			limit = 10
		}

		offset, err := strconv.Atoi(c.Query("start"))
		if err != nil {
			offset = 0
		}

		order := c.Request.URL.Query().Get("order[0][dir]")
		if order != "asc" {
			order = "desc"
		}

		orderCol := c.Request.URL.Query().Get("order[0][column]")

		switch orderCol {
		case "0":
			orderCol = "id"
		case "1":
			orderCol = "host"
		case "2":
			orderCol = "user_id"
		case "3":
			orderCol = "name"
		case "4":
			orderCol = "command"
		}

		search := c.Request.URL.Query().Get("search[value]")

		var sessions []config.Session
		ref := env.DB.Preload("User", func(db *gorm.DB) *gorm.DB {
			return db.Select([]string{"id", "email"})
		}).Select([]string{
			"id",
			"user_id",
			"time",
			"name",
			"host",
			"hostname",
			"users",
			"command",
		})

		userIds := make([]uint, 0)

		addWhere := func(db *gorm.DB) *gorm.DB {
			if search == "" {
				return db
			}

			ref := db.Where(
				"name like ? OR host like ? OR hostname like ? OR users like ? OR command like ? OR user_id in (?)",
				search,
				search,
				search,
				search,
				search,
				userIds,
			)

			return ref
		}

		if search != "" {
			search = "%" + search + "%"

			newIds := make([]uint, 0)
			var users []config.User
			env.DB.Table("users").Select("id").Where("email like ?", search).Find(&users)

			for _, u := range users {
				newIds = append(newIds, u.ID)
			}

			userIds = newIds
			ref = addWhere(ref)
		}

		ref.Order(fmt.Sprintf("%s %s", orderCol, order)).Limit(limit).Offset(offset).Find(&sessions)

		arrayData := make([]interface{}, 0)
		for _, v := range sessions {
			innerData := make([]interface{}, 8)

			innerData[0] = v.ID
			innerData[1] = fmt.Sprintf("%s - %s", v.Host, v.Hostname)
			innerData[2] = v.User.Email
			innerData[3] = v.Users
			innerData[4] = v.Name
			innerData[5] = v.Name
			innerData[6] = v.Name
			innerData[7] = v.Command

			arrayData = append(arrayData, innerData)
		}

		draw, err := strconv.Atoi(c.Query("draw"))
		if err != nil {
			draw = 1
		}

		var filteredSessions int
		var allSessions int

		env.DB.Table("sessions").Where(map[string]interface{}{"deleted_at": nil}).Count(&allSessions)
		addWhere(env.DB.Table("sessions").Where(map[string]interface{}{"deleted_at": nil})).Count(&filteredSessions)

		retData := make(map[string]interface{})

		retData["draw"] = draw
		retData["recordsTotal"] = allSessions
		retData["recordsFiltered"] = filteredSessions
		retData["data"] = arrayData

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
			limit, err := strconv.Atoi(c.Query("length"))
			if err != nil {
				limit = 10
			}

			offset, err := strconv.Atoi(c.Query("start"))
			if err != nil {
				offset = 0
			}

			order := c.Request.URL.Query().Get("order[0][dir]")
			if order != "asc" {
				order = "desc"
			}

			orderCol := c.Request.URL.Query().Get("order[0][column]")

			switch orderCol {
			case "0":
				orderCol = "id"
			case "1":
				orderCol = "host"
			case "2":
				orderCol = "user_id"
			case "3":
				orderCol = "name"
			case "4":
				orderCol = "command"
			}

			search := c.Request.URL.Query().Get("search[value]")

			var livesessions []config.LiveSession

			ref := env.DB.Preload("User", func(db *gorm.DB) *gorm.DB {
				return db.Select([]string{"id", "email"})
			}).Select([]string{
				"id",
				"user_id",
				"time",
				"name",
				"host",
				"hostname",
				"ws",
				"command",
			}).Where("id in (?)", env.DB.Table("live_sessions").Select([]string{"MAX(id) as id"}).Group("name").QueryExpr())

			type res struct {
				Name  string
				Count int
			}

			var results []res
			env.DB.Table("live_sessions").Select([]string{"name", "count(name) as count"}).Group("name").Having("count(name) > ?", 1).Scan(&results)

			resultsMap := make(map[string]res)
			for _, v := range results {
				resultsMap[v.Name] = v
			}

			userIds := make([]uint, 0)

			addWhere := func(db *gorm.DB) *gorm.DB {
				if search == "" {
					return db
				}

				ref := db.Where(
					"name like ? OR host like ? OR hostname like ? OR command like ? OR user_id in (?)",
					search,
					search,
					search,
					search,
					userIds,
				)

				return ref
			}

			if search != "" {
				search = "%" + search + "%"

				newIds := make([]uint, 0)
				var users []config.User
				env.DB.Table("users").Select("id").Where("email like ?", search).Find(&users)

				for _, u := range users {
					newIds = append(newIds, u.ID)
				}

				userIds = newIds
				ref = addWhere(ref)
			}

			ref.Order(fmt.Sprintf("%s %s", orderCol, order)).Limit(limit).Offset(offset).Find(&livesessions)

			newSessions := make(map[string]config.LiveSession)
			arrayData := make([]interface{}, 0)
			for _, v := range livesessions {
				if _, ok := newSessions[v.Name]; !ok {
					newSessions[v.Name] = v

					innerData := make([]interface{}, 7)

					innerData[0] = v.ID
					innerData[1] = fmt.Sprintf("%s - %s", v.Host, v.Hostname)
					innerData[2] = v.User.Email
					innerData[3] = v.Name
					innerData[6] = v.Command

					if v2, ok := resultsMap[v.Name]; ok {
						innerData[4] = v.WS + ";" + strconv.Itoa(v2.Count)
						innerData[5] = v.WS + ";" + strconv.Itoa(v2.Count)
					} else {
						innerData[4] = v.WS + ";1"
						innerData[5] = v.WS + ";1"
					}

					arrayData = append(arrayData, innerData)
				}
			}

			draw, err := strconv.Atoi(c.Query("draw"))
			if err != nil {
				draw = 1
			}

			var filteredSessions int
			var allSessions int

			env.DB.Table("live_sessions").Where(map[string]interface{}{"deleted_at": nil}).Where("id in (?)", env.DB.Table("live_sessions").Select([]string{"MAX(id) as id"}).Group("name").QueryExpr()).Count(&allSessions)
			addWhere(env.DB.Table("live_sessions").Where(map[string]interface{}{"deleted_at": nil}).Where("id in (?)", env.DB.Table("live_sessions").Select([]string{"MAX(id) as id"}).Group("name").QueryExpr())).Count(&filteredSessions)

			retData["draw"] = draw
			retData["recordsTotal"] = allSessions
			retData["recordsFiltered"] = filteredSessions

			retData["data"] = arrayData

			c.JSON(http.StatusOK, retData)
			return
		}

		i := 1
		newSessions := make([]interface{}, 0)
		env.SSHProxyClients.Range(func(key interface{}, value interface{}) bool {
			client := value.(*config.SSHProxyClient)
			serverClient := client.SSHServerClient

			client.Mutex.Lock()
			if client.SSHServerClient.User != nil && len(client.SSHShellSessions) > 0 {
				innerData := make([]interface{}, 7)

				innerData[0] = i
				innerData[1] = fmt.Sprintf("%s - %s", client.SSHServerClient.ProxyTo, client.SSHServerClient.ProxyToHostname)
				innerData[2] = client.SSHServerClient.User.Email
				innerData[3] = serverClient.Client.RemoteAddr().String()
				innerData[5] = key.(string) + ";" + strconv.Itoa(len(client.SSHShellSessions))
				innerData[6] = key.(string) + ";" + strconv.Itoa(len(client.SSHShellSessions))

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
				innerData[4] = wholeCommand
				newSessions = append(newSessions, innerData)
				i++
			}
			client.Mutex.Unlock()

			return true
		})

		retData["data"] = newSessions

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

func checkOtp(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		sessionUser := session.Get("user").(*config.User)
		retData := make(map[string]interface{})

		url := c.PostForm("url")
		code := c.PostForm("code")

		var secret string
		if sessionUser.OTPSecret == "" {
			secret = url
		} else {
			secret = sessionUser.OTPSecret
		}

		key, err := otp.NewKeyFromURL(secret)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		if totp.Validate(code, key.Secret()) {
			if sessionUser.OTPSecret == "" {
				env.DB.Model(&sessionUser).Update("otp_secret", key.String())

				c.Redirect(http.StatusFound, "/logout")
				c.Abort()
				return
			}

			session.Set("otpauthed", true)
			session.Save()

			c.Redirect(http.StatusFound, "/sessions")
			c.Abort()
			return
		}

		retData["status"] = "error"
		retData["message"] = "try again"

		c.JSON(http.StatusUnauthorized, retData)
	}
}

func setupotp(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		sessionUser := session.Get("user").(*config.User)

		if sessionUser.OTPSecret != "" {
			if otpAuthed := session.Get("otpauthed"); otpAuthed == nil || !(otpAuthed.(bool)) {
				c.Redirect(http.StatusFound, "/otp")
				c.Abort()
				return
			}
		}

		var key *otp.Key
		var err error
		if sessionUser.OTPSecret != "" {
			key, err = otp.NewKeyFromURL(sessionUser.OTPSecret)
		} else {
			key, err = totp.Generate(totp.GenerateOpts{
				Issuer:      env.Vconfig.GetString("otp.issuer"),
				AccountName: sessionUser.Email,
			})
		}

		if err != nil {
			env.Red.Println(err)
		}

		var buf bytes.Buffer
		img, err := key.Image(200, 200)
		if err != nil {
			env.Red.Println(err)
		}

		png.Encode(&buf, img)

		retData := make(map[string]interface{})
		retData["otpurl"] = key.String()
		retData["imageurl"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

		c.JSON(http.StatusOK, retData)
	}
}

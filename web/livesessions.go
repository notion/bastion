package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	"github.com/koding/websocketproxy"
	"github.com/notion/bastion/config"
)

func liveSession(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		if env.Vconfig.GetBool("multihost.enabled") {
			liveSessionMultiHost(env)(c)
			return
		}

		retData := make(map[string]interface{})

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
				innerData[4] = key.(string) + ";" + strconv.Itoa(len(client.SSHShellSessions))
				innerData[5] = key.(string) + ";" + strconv.Itoa(len(client.SSHShellSessions))

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

							if wholeCommand != "" {
								wholeCommand += ", " + command
							} else {
								wholeCommand += command
							}
							break
						}
					}
				}
				innerData[6] = wholeCommand
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

func liveSessionMultiHost(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		retData := make(map[string]interface{})
		limit, offset, order, orderCol, search := getDataTablesParams(c)

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
		}).Where("id in (?)", env.DB.Table("live_sessions").Select([]string{"MAX(id) as id"}).Group("name").Where(map[string]interface{}{"deleted_at": nil}).QueryExpr())

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
}

func disconnectLiveSession(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		authcode, pathKey, sidKey := getLiveSessionParams(c)

		if env.Vconfig.GetBool("multihost.enabled") && authcode == "" {
			disconnectLiveSessionMultiHost(env)(c)
			return
		}

		retData := make(map[string]interface{})

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

func disconnectLiveSessionMultiHost(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		authcode, pathKey, _ := getLiveSessionParams(c)

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
		} else if authcode != dblivesession.AuthCode {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{"status": false, "error": "Invalid auth code."})
			return
		} else {
			disconnectLiveSession(env)(c)
			return
		}
	}
}

func liveSessionWS(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		authcode, pathKey, sidKey := getLiveSessionParams(c)

		if env.Vconfig.GetBool("multihost.enabled") && authcode == "" {
			liveSessionWSMultiHost(env)(c)
			return
		}

		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

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

func liveSessionWSMultiHost(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		authcode, pathKey, _ := getLiveSessionParams(c)

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
		} else if authcode != dblivesession.AuthCode {
			c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{"status": false, "error": "Invalid auth code."})
			return
		} else {
			liveSessionWS(env)(c)
			return
		}
	}
}

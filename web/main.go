package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"github.com/fatih/color"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/notion/trove_ssh_bastion/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	storeName = "session"
	store     = sessions.NewCookieStore(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32))
)

func Serve(addr string, env *config.Env) {
	templs, err := template.ParseGlob("web/templates/*")
	if err != nil {
		log.Println("ERROR PARSING TEMPLATE GLOB:", err)
	}

	store.MaxAge(1 * 60 * 60)

	conf := oauth2.Config{
		ClientID:     "***REMOVED***",
		ClientSecret: "***REMOVED***",
		RedirectURL:  "http://localhost:8080",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	gob.Register(&oauth2.Token{})
	gob.Register(&config.User{})

	r := mux.NewRouter()

	authedRouter := r.PathPrefix("/").Subrouter()
	authedRouter.Use(authMiddleware)

	r.HandleFunc("/", index(env, conf))
	authedRouter.HandleFunc("/sessions", sessionTempl(env, templs))
	authedRouter.HandleFunc("/livesessions", liveSessionTempl(env, templs))
	authedRouter.HandleFunc("/users", userTempl(env, templs))
	authedRouter.HandleFunc("/api/users", user(env))
	authedRouter.HandleFunc("/api/user/{id}", updateUser(env))
	authedRouter.HandleFunc("/api/livesessions", liveSession(env))
	authedRouter.HandleFunc("/api/ws/livesessions/{id}", liveSessionWS(env))
	authedRouter.HandleFunc("/api/sessions", session(env))
	authedRouter.HandleFunc("/api/sessions/{id}", sessionId(env))

	srv := &http.Server{
		Handler: logHTTP(r),
		Addr:    addr,
	}

	color.Set(color.FgGreen)
	log.Println("Running HTTP server at:", addr)
	color.Unset()

	color.Set(color.FgRed)
	log.Fatal(srv.ListenAndServe())
	color.Unset()
}

func index(env *config.Env, conf oauth2.Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")

		session, err := store.Get(r, "session")
		if err != nil {
			log.Println("Can't get session from request", err)
		}

		if code == "" {
			if k, ok := session.Values["loggedin"]; ok {
				if k.(bool) {
					http.Redirect(w, r, "/sessions", http.StatusFound)
					return
				}
			}

			state := sha256.Sum256(securecookie.GenerateRandomKey(32))

			session.Values["state"] = base64.URLEncoding.EncodeToString(state[:])
			err = session.Save(r, w)
			if err != nil {
				log.Println("Error saving session:", err)
			}

			http.Redirect(w, r, conf.AuthCodeURL(session.Values["state"].(string)), http.StatusFound)
			return
		} else {
			if r.URL.Query().Get("state") == session.Values["state"] {
				token, err := conf.Exchange(context.TODO(), code)
				if err != nil {
					log.Println("ISSUE EXCHANGING CODE:", err)
				}

				client := conf.Client(context.TODO(), token)

				resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
				if err != nil {
					log.Println("ERROR GETTING USER INFO", err)
				}
				defer resp.Body.Close()

				userData := make(map[string]interface{})

				data, _ := ioutil.ReadAll(resp.Body)

				err = json.Unmarshal(data, &userData)
				if err != nil {
					log.Println("Unable to unmarshal user info from google", err)
				}

				var user config.User

				env.DB.First(&user, "email = ?", userData["email"].(string))

				user.Email = userData["email"].(string)
				user.AuthToken = token.AccessToken

				session.Values["user"] = user
				session.Values["auth"] = token
				session.Values["loggedin"] = true
				err = session.Save(r, w)
				if err != nil {
					log.Println("Error saving session:", err)
				}

				env.DB.Save(&user)

				http.Redirect(w, r, "/sessions", http.StatusFound)
				return
			} else {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
	}
}

func sessionTempl(env *config.Env, templs *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			log.Println("Can't get session from request", err)
		}

		userData := session.Values["user"].(*config.User)

		templs.Lookup("session").Execute(w, userData)
	}
}

func session(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionsData := make([]*config.Session, 0)

		ctx := context.Background()
		objectsIterator := env.LogsBucket.Objects(ctx, nil)

		var iteratorError error

		for iteratorError == nil {
			var dbSession config.Session
			var dbUser config.User

			object, err := objectsIterator.Next()

			if err != nil {
				iteratorError = err
				break
			}

			env.DB.Select([]string{"user_id", "time", "name", "host"}).First(&dbSession, "name = ?", object.Name).Select([]string{"email"}).Related(&dbUser, "UserID")

			dbSession.User = &dbUser

			sessionsData = append(sessionsData, &dbSession)
		}

		retData := make(map[string]interface{})

		retData["status"] = "ok"
		retData["sessions"] = sessionsData

		returnJson(w, r, retData, 0)
	}
}

func sessionId(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		ctx := context.Background()

		reader, err := env.LogsBucket.Object(vars["id"]).ReadCompressed(true).NewReader(ctx)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Transfer-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			io.Copy(w, reader)
		}
	}
}

func liveSessionTempl(env *config.Env, templs *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			log.Println("Can't get session from request", err)
		}

		userData := session.Values["user"].(*config.User)

		templs.Lookup("livesession").Execute(w, userData)
	}
}

func liveSession(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		retData := make(map[string]interface{})

		var newSessions []interface{}
		for k, client := range env.SshProxyClients {
			sessionData := make(map[string]interface{})
			sessionData["Name"] = k
			sessionData["Host"] = client.SshServerClient.ProxyTo
			sessionData["User"] = client.SshServerClient.User.Email
			newSessions = append(newSessions, sessionData)
		}

		retData["status"] = "ok"
		retData["livesessions"] = newSessions

		jsonData, err := json.Marshal(retData)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)
	}
}

func liveSessionWS(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		pathKey := vars["id"]

		c, err := upgrader.Upgrade(w, r, nil)

		color.Set(color.FgBlue)
		log.Println("New WebSocket Connection From:", r.RemoteAddr)
		log.Println("Path:", pathKey)
		color.Unset()

		if err != nil {
			color.Set(color.FgRed)
			log.Println("Upgrade error:", err)
			color.Unset()
			return
		}

		if proxyClient, ok := env.SshProxyClients[pathKey]; ok {
			if _, ok := env.WebsocketClients[pathKey]; !ok {
				env.WebsocketClients[pathKey] = make(map[string]*config.WsClient)
			}

			env.WebsocketClients[pathKey][c.RemoteAddr().String()] = &config.WsClient{
				Client: c,
			}

			wsWriter, err := c.NextWriter(websocket.TextMessage)
			if err != nil {
				log.Println("Error establishing ws writer in playback")
			}

			for _, frame := range proxyClient.Closer.Cast.Frames {
				wsWriter.Write([]byte(frame.Data))
			}

			wsWriter.Close()
		} else {
			c.Close()
			return
		}

		for {
			_, p, err := c.ReadMessage()
			if err != nil {
				color.Set(color.FgRed)
				log.Println("wsReader error:", err)
				color.Unset()

				break
			}

			if _, ok := env.SshProxyClients[pathKey]; ok {
				sshProxyClient := *env.SshProxyClients[pathKey].SshShellSession

				if sshProxyClient != nil {
					_, err = sshProxyClient.Write(p)
					if err != nil {
						color.Set(color.FgRed)
						log.Println("SSH Session Write Error:", err)
						color.Unset()

						break
					}
				}
			}
		}

		defer func() {
			c.Close()

			delete(env.WebsocketClients[pathKey], c.RemoteAddr().String())

			color.Set(color.FgMagenta)
			log.Println("Closed WebSocket Connection From:", r.RemoteAddr)
			color.Unset()
		}()
	}
}

func userTempl(env *config.Env, templs *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			log.Println("Can't get session from request", err)
		}

		userData := session.Values["user"].(*config.User)

		templs.Lookup("user").Execute(w, userData)
	}
}

func user(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		retData := make(map[string]interface{})
		var users []config.User

		env.DB.Find(&users)

		retData["status"] = "ok"
		retData["users"] = users

		returnJson(w, r, retData, 0)
	}
}

func updateUser(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			http.Redirect(w, r, "/users", http.StatusFound)
			return
		}

		vars := mux.Vars(r)
		retData := make(map[string]interface{})
		var user config.User

		env.DB.Find(&user, vars["id"])
		r.ParseForm()

		decoded, err := base64.StdEncoding.DecodeString(r.Form.Get("privatekey"))
		if err != nil {
			log.Println("Error base64 decoding string.", err)
		}

		user.Email = r.Form.Get("email")
		user.PrivateKey = decoded
		user.Authorized = r.Form.Get("authorized") == "on"

		env.DB.Save(&user)

		retData["status"] = "ok"
		retData["user"] = user

		returnJson(w, r, retData, 0)
	}
}
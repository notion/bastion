package web

import (
	"net/http"
	"github.com/fatih/color"
	"log"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/notion/trove_ssh_bastion/config"
	"encoding/json"
	"html/template"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"context"
	"fmt"
	"io"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func logHTTP(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		color.Set(color.FgYellow)
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		color.Unset()

		handler.ServeHTTP(w, r)
	})
}

func Serve(addr string, env *config.Env) {
	conf := oauth2.Config{
		ClientID: "***REMOVED***",
		ClientSecret: "***REMOVED***",
		RedirectURL: "http://localhost:8080",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	r := mux.NewRouter()

	templs, err := template.ParseGlob("web/templates/*")
	if err != nil {
		log.Println("ERROR PARSING TEMPLATE GLOB:", err)
	}

	r.HandleFunc("/", index(env, conf))
	r.HandleFunc("/sessions", sessionTempl(env, templs))
	r.HandleFunc("/livesessions", liveSessionTempl(env, templs))
	r.HandleFunc("/api/livesessions", liveSession(env))
	r.HandleFunc("/api/ws/livesessions/{id}", liveSessionWS(env))
	r.HandleFunc("/api/sessions", session(env))
	r.HandleFunc("/api/sessions/{id}", sessionId(env))

	srv := &http.Server{
		Handler:      logHTTP(r),
		Addr:         addr,
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
		if code == "" {
			http.Redirect(w, r, conf.AuthCodeURL("state"), http.StatusFound)
		} else {
			token, err := conf.Exchange(context.TODO(), code)
			if err != nil {
				log.Println("ISSUE EXCHANGING CODE:", err)
			}

			w.Write([]byte(fmt.Sprintf("%+v", token)))
		}
	}
}

func sessionTempl(env *config.Env, templs *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		templs.Lookup("session").Execute(w, nil)
	}
}


func session(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sessions := make([]string, 0)

		ctx := context.Background()
		objectsIterator := env.LogsBucket.Objects(ctx, nil)

		var iteratorError error

		for iteratorError == nil {
			object, err := objectsIterator.Next()

			if err != nil {
				iteratorError = err
				break
			}

			sessions = append(sessions, object.Name)
		}

		retData := make(map[string]interface{})

		retData["status"] = "ok"
		retData["sessions"] = sessions

		jsonData, err := json.Marshal(retData)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)
	}
}

func sessionId(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		ctx := context.Background()

		reader, err := env.LogsBucket.Object(vars["id"]).NewReader(ctx)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusOK)
			io.Copy(w, reader)
		}
	}
}

func liveSessionTempl(env *config.Env, templs *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		templs.Lookup("livesession").Execute(w, nil)
	}
}

func liveSession(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		retData := make(map[string]interface{})

		var newSessions []interface{}
		for k, _ := range env.SshProxyClients {
			sessionData := make(map[string]interface{})
			sessionData["id"] = k
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

		if _, ok := env.SshProxyClients[pathKey]; ok {
			if _, ok := env.WebsocketClients[pathKey]; !ok {
				env.WebsocketClients[pathKey] = make(map[string]*config.WsClient)
			}

			env.WebsocketClients[pathKey][c.RemoteAddr().String()] = &config.WsClient{
				Client: c,
			}
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

		defer func() {
			c.Close()

			delete(env.WebsocketClients[pathKey], c.RemoteAddr().String())

			color.Set(color.FgMagenta)
			log.Println("Closed WebSocket Connection From:", r.RemoteAddr)
			color.Unset()
		}()
	}
}
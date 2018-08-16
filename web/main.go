package web

import (
	"net/http"
	"github.com/fatih/color"
	"log"
	"github.com/gorilla/mux"
	"github.com/notion/trove_ssh_bastion/config"
	"encoding/json"
	"html/template"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"context"
	"fmt"
)

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
		templs.Lookup("cast").Execute(w, nil)
	}
}


func session(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var sessions []config.Session
		retData := make(map[string]interface{})

		env.DB.Find(&sessions)

		var newSessions []interface{}
		for _, x := range sessions {
			sessionData := make(map[string]interface{})
			sessionData["id"] = x.ID
			newSessions = append(newSessions, sessionData)
		}

		retData["status"] = "ok"
		retData["sessions"] = newSessions

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

		var session config.Session

		if env.DB.First(&session, vars["id"]).RecordNotFound() {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(session.Cast))
		}
	}
}

package web

import (
	"net/http"
	"github.com/fatih/color"
	"log"
	"github.com/gorilla/mux"
	"github.com/notion/trove_ssh_bastion/config"
	"fmt"
	"encoding/json"
	"html/template"
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
	r := mux.NewRouter()

	templs, err := template.ParseGlob("web/templates/*")
	if err != nil {
		log.Println("ERROR PARSING TEMPLATE GLOB:", err)
	}

	r.HandleFunc("/", index(env))
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

func index(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello world!\n"))

		for _, v := range env.SshServerClients {
			w.Write([]byte(v.Username + "\n"))
			w.Write([]byte(v.Password + "\n"))
			w.Write([]byte(v.Client.RemoteAddr().String() + "\n"))
			w.Write([]byte(fmt.Sprintf("%#v\n", v) + "\n"))
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

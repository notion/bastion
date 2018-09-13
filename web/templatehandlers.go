package web

import (
	"github.com/notion/trove_ssh_bastion/config"
	"html/template"
	"log"
	"net/http"
)

func sessionTempl(env *config.Env, templs *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			env.Red.Println("Can't get session from request", err)
		}

		userData := session.Values["user"].(*config.User)

		templs.Lookup("session").Execute(w, userData)
	}
}

func liveSessionTempl(env *config.Env, templs *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			env.Red.Println("Can't get session from request", err)
		}

		userData := session.Values["user"].(*config.User)

		templs.Lookup("livesession").Execute(w, userData)
	}
}

func userTempl(env *config.Env, templs *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			env.Red.Println("Can't get session from request", err)
		}

		userData := session.Values["user"].(*config.User)

		templs.Lookup("user").Execute(w, userData)
	}
}

func noaccessTempl(env *config.Env, templs *template.Template) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			env.Red.Println("Can't get session from request", err)
		}

		userData := session.Values["user"].(*config.User)
		log.Printf("%+v", userData)
		log.Printf("%+v", session.Values)

		var fullUser config.User

		if env.DB.First(&fullUser, userData.ID).RecordNotFound() {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		templs.Lookup("noaccess").Execute(w, userData)
	}
}

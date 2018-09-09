package web

import (
	"encoding/gob"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/gorilla/websocket"
	"github.com/notion/trove_ssh_bastion/config"
	"golang.org/x/oauth2"
	"html/template"
	"net/http"
	"net/http/pprof"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	storeName = "session"
	//store     = sessions.NewCookieStore(securecookie.GenerateRandomKey(32), securecookie.GenerateRandomKey(32))
	store = sessions.NewCookieStore([]byte("foobar"))
)

func Serve(addr string, env *config.Env) {
	oauthConfig := oauth2.Config{}
	env.Vconfig.SetDefault("OauthCredentials", &oauthConfig)
	env.Vconfig.UnmarshalKey("OauthCredentials", &oauthConfig)

	templs, err := template.ParseGlob("web/templates/*")
	if err != nil {
		env.Red.Println("ERROR PARSING TEMPLATE GLOB:", err)
	}

	store.MaxAge(1 * 60 * 60)

	gob.Register(&oauth2.Token{})
	gob.Register(&config.User{})

	r := mux.NewRouter()

	r.PathPrefix("/debug/pprof/").HandlerFunc(pprof.Index)

	authedRouter := r.PathPrefix("/").Subrouter()
	authedRouter.Use(authMiddleware)

	r.HandleFunc("/", index(env, oauthConfig))
	authedRouter.HandleFunc("/sessions", sessionTempl(env, templs))
	authedRouter.HandleFunc("/livesessions", liveSessionTempl(env, templs))
	authedRouter.HandleFunc("/users", userTempl(env, templs))

	authedRouter.HandleFunc("/api/users", user(env))
	authedRouter.HandleFunc("/api/user/{id}", updateUser(env))
	authedRouter.HandleFunc("/api/keys/{user_id}", userCerts(env))
	authedRouter.HandleFunc("/api/livesessions", liveSession(env))
	authedRouter.HandleFunc("/api/ws/livesessions/{id}", liveSessionWS(env))
	authedRouter.HandleFunc("/api/sessions", session(env))
	authedRouter.HandleFunc("/api/sessions/{id}", sessionId(env))

	srv := &http.Server{
		Handler: logHTTP(r, env),
		Addr:    addr,
	}

	env.Green.Println("Running HTTP server at:", addr)

	env.Red.Fatal(srv.ListenAndServe())
}
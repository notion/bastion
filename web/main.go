package web

import (
	"net/http"
	"github.com/fatih/color"
	"log"
	"github.com/gorilla/mux"
	"github.com/notion/trove_ssh_bastion/config"
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
	r := mux.NewRouter()

	r.HandleFunc("/", index(env))

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

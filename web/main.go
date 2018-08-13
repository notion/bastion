package web

import (
	"net/http"
	"github.com/fatih/color"
	"log"
	"github.com/gorilla/mux"
	"github.com/notion/trove_ssh_bastion/config"
)

func logHTTP(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		color.Set(color.FgYellow)
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
		color.Unset()

		handler.ServeHTTP(w, r)
	})
}

func index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Hello world!"))
}

func Serve(addr string, env *config.Env) {
	r := mux.NewRouter()

	r.HandleFunc("/", index)

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
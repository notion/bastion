package web

import (
	"encoding/json"
	"github.com/notion/trove_ssh_bastion/config"
	"net/http"
)

func logHTTP(handler http.Handler, env *config.Env) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.Yellow.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)

		handler.ServeHTTP(w, r)
	})
}

func returnErr(w http.ResponseWriter, r *http.Request, err error, code int) {
	if code == 0 {
		code = http.StatusInternalServerError
	}

	http.Error(w, err.Error(), code)
	return
}

func returnJson(w http.ResponseWriter, r *http.Request, data interface{}, status int) {
	if status == 0 {
		status = http.StatusOK
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "    ")

	encoder.Encode(data)
	return
}
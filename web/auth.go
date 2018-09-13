package web

import (
	"github.com/notion/trove_ssh_bastion/config"
	"net/http"
	"regexp"
)

func authMiddleware(env *config.Env) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := store.Get(r, storeName)
			if err != nil {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}

			if auth, ok := session.Values["loggedin"]; ok {
				userData := session.Values["user"].(*config.User)

				if auth.(bool) {
					match, _ := regexp.MatchString("^\\/api\\/users\\/(.*)\\/keys$", r.URL.Path)
					if userData.Admin || r.URL.Path == "/noaccess" || match {
						next.ServeHTTP(w, r)
						return
					} else {
						http.Redirect(w, r, "/noaccess", http.StatusFound)
						return
					}
				}
			}

			http.Redirect(w, r, "/", http.StatusFound)
			return
		})
	}
}

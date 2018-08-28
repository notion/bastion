package web

import (
	"net/http"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//next.ServeHTTP(w, r)
		//return

		session, err := store.Get(r, storeName)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		if auth, ok := session.Values["loggedin"]; ok {
			if auth.(bool) {
				next.ServeHTTP(w, r)
				return
			}
		}

		http.Redirect(w, r, "/", http.StatusFound)
	})
}

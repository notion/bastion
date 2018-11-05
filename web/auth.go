package web

import (
	"net/http"
	"regexp"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/notion/bastion/config"
)

var (
	passPathsIfAuthed = map[string]bool{
		"/noaccess": true,
	}

	passPaths = map[string]bool{
		"/":       true,
		"/logout": true,
	}
)

func authMiddleware(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		if auth := session.Get("loggedin"); auth != nil {
			userData := session.Get("user").(*config.User)

			if auth.(bool) {
				match, _ := regexp.MatchString("^\\/api\\/users\\/(.*)\\/keys$", c.Request.URL.Path)
				if userData.Admin || passPathsIfAuthed[c.Request.URL.Path] || passPaths[c.Request.URL.Path] || match {
					c.Next()
					return
				}

				c.Redirect(http.StatusFound, "/noaccess")
				return
			}
		}

		if passPaths[c.Request.URL.Path] {
			c.Next()
		} else {
			c.Redirect(http.StatusFound, "/")
		}

		return
	}
}

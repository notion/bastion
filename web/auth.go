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
		"/otp":      true,
		"/setupotp": true,
	}

	passPaths = map[string]bool{
		"/":       true,
		"/logout": true,
	}
)

func authMiddleware(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)

		auth := session.Get("loggedin")
		if otpAuth := session.Get("otpauthed"); otpAuth != nil {
			userData := session.Get("user").(*config.User)

			if otpAuth.(bool) {
				if auth.(bool) {
					match, _ := regexp.MatchString("^\\/api\\/users\\/(.*)\\/keys$", c.Request.URL.Path)
					if userData.Admin || passPathsIfAuthed[c.Request.URL.Path] || passPaths[c.Request.URL.Path] || match {
						return
					}

					c.Redirect(http.StatusFound, "/noaccess")
					return
				}
			}
		}

		if passPaths[c.Request.URL.Path] {
			return
		}

		c.Redirect(http.StatusFound, "/")
		return
	}
}

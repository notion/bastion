package web

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/notion/bastion/config"
)

var (
	passPathsIfAuthedAndOtp = map[string]bool{
		"/noaccess": true,
	}

	passPathsIfAuthed = map[string]bool{
		"/otp":          true,
		"/api/otp":      true,
		"/setupotp":     true,
		"/api/setupotp": true,
	}

	passPaths = map[string]bool{
		"/":       true,
		"/logout": true,
	}
)

func authMiddleware(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		path := strings.TrimSpace(c.Request.URL.Path)
		session := sessions.Default(c)

		auth := session.Get("loggedin")
		otpAuth := session.Get("otpauthed")
		if otpAuth != nil {
			userData := session.Get("user").(*config.User)

			if auth.(bool) {
				if env.Vconfig.GetBool("otp.enabled") && !(otpAuth.(bool)) && !passPaths[path] && !passPathsIfAuthed[path] {
					c.Redirect(http.StatusFound, "/otp")
					c.Abort()
					return
				}

				match, _ := regexp.MatchString("^\\/api\\/users\\/(.*)\\/keys$", path)
				if userData.Admin || passPathsIfAuthed[path] || passPaths[path] || passPathsIfAuthedAndOtp[path] || match {
					return
				}

				c.Redirect(http.StatusFound, "/noaccess")
				c.Abort()
				return
			}
		}

		if passPaths[path] {
			return
		}

		c.Redirect(http.StatusFound, "/")
		c.Abort()
		return
	}
}

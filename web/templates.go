package web

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/notion/bastion/config"
)

func SessionTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		c.HTML(http.StatusOK, "session", userData)
	}
}

func LiveSessionTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		c.HTML(http.StatusOK, "livesession", userData)
	}
}

func UserTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		c.HTML(http.StatusOK, "user", userData)
	}
}

func AuthRuleTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		c.HTML(http.StatusOK, "authrule", userData)
	}
}

func authTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		var fullUser config.User

		if env.DB.First(&fullUser, userData.ID).RecordNotFound() {
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		c.HTML(http.StatusOK, "index", userData)
	}
}

func OtpTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		if userData.OTPSecret == "" {
			c.Redirect(http.StatusFound, "/setupotp")
			c.Abort()
			return
		}

		c.HTML(http.StatusOK, "otp", userData)
	}
}

func SetupOtpTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		if userData.OTPSecret != "" {
			if otpAuthed := session.Get("otpauthed"); otpAuthed == nil || !otpAuthed.(bool) {
				c.Redirect(http.StatusFound, "/otp")
				c.Abort()
				return
			}
		}

		c.HTML(http.StatusOK, "setupotp", userData)
	}
}

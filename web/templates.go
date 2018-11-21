package web

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/notion/bastion/config"
)

func sessionTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		c.HTML(http.StatusOK, "session", userData)
	}
}

func liveSessionTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		c.HTML(http.StatusOK, "livesession", userData)
	}
}

func userTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		c.HTML(http.StatusOK, "user", userData)
	}
}

func noaccessTempl(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userData := session.Get("user").(*config.User)

		var fullUser config.User

		if env.DB.First(&fullUser, userData.ID).RecordNotFound() {
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		c.HTML(http.StatusOK, "noaccess", userData)
	}
}

func otpTempl(env *config.Env) func(c *gin.Context) {
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

func setupOtpTempl(env *config.Env) func(c *gin.Context) {
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

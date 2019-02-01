package web

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/notion/bastion/config"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	passPathsIfAuthedAndOtp = map[string]bool{
		"/authenticated": true,
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

				c.Redirect(http.StatusFound, "/authenticated")
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

func checkOtp(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		sessionUser := session.Get("user").(*config.User)
		retData := make(map[string]interface{})

		url := c.PostForm("url")
		code := c.PostForm("code")

		var secret string
		if sessionUser.OTPSecret == "" {
			secret = url
		} else {
			secret = sessionUser.OTPSecret
		}

		key, err := otp.NewKeyFromURL(secret)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		if totp.Validate(code, key.Secret()) {
			if sessionUser.OTPSecret == "" {
				env.DB.Model(&sessionUser).Update("otp_secret", key.String())

				c.Redirect(http.StatusFound, "/logout")
				c.Abort()
				return
			}

			session.Set("otpauthed", true)
			session.Save()

			c.Redirect(http.StatusFound, "/authenticated")
			c.Abort()
			return
		}

		retData["status"] = "error"
		retData["message"] = "try again"

		c.JSON(http.StatusUnauthorized, retData)
	}
}

func setupotp(env *config.Env) func(c *gin.Context) {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		sessionUser := session.Get("user").(*config.User)

		if sessionUser.OTPSecret != "" {
			if otpAuthed := session.Get("otpauthed"); otpAuthed == nil || !(otpAuthed.(bool)) {
				c.Redirect(http.StatusFound, "/otp")
				c.Abort()
				return
			}
		}

		var key *otp.Key
		var err error
		if sessionUser.OTPSecret != "" {
			key, err = otp.NewKeyFromURL(sessionUser.OTPSecret)
		} else {
			key, err = totp.Generate(totp.GenerateOpts{
				Issuer:      env.Vconfig.GetString("otp.issuer"),
				AccountName: sessionUser.Email,
			})
		}

		if err != nil {
			env.Red.Println(err)
		}

		var buf bytes.Buffer
		img, err := key.Image(200, 200)
		if err != nil {
			env.Red.Println(err)
		}

		png.Encode(&buf, img)

		retData := make(map[string]interface{})
		retData["otpurl"] = key.String()
		retData["imageurl"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

		c.JSON(http.StatusOK, retData)
	}
}

package web

import (
	"encoding/gob"
	"net/http"
	"runtime"

	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/notion/bastion/config"
	"golang.org/x/oauth2"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

// Serve Starts the web server and all of its handlers
func Serve(addr string, env *config.Env) {
	oauthConfig := oauth2.Config{}
	env.Vconfig.SetDefault("OauthCredentials", &oauthConfig)
	env.Vconfig.UnmarshalKey("OauthCredentials", &oauthConfig)

	store := cookie.NewStore([]byte(env.Vconfig.GetString("cookiesecret")))
	store.Options(sessions.Options{
		MaxAge: 1 * 60 * 60,
		Path:   "/",
	})

	gob.Register(&oauth2.Token{})
	gob.Register(&config.User{})

	r := gin.Default()
	r.Use(sessions.Sessions("session", store))
	r.LoadHTMLGlob("web/templates/*")

	if env.Vconfig.GetBool("debug.web.enabled") {
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(1)

		pprof.Register(r)
		r.GET("/api/opensessions", openSessions(env))
	}

	authedGroup := r.Group("/", authMiddleware(env))
	{
		authedGroup.GET("", index(env, oauthConfig))
		authedGroup.GET("/logout", logout(env))
		authedGroup.GET("/sessions", sessionTempl(env))
		authedGroup.GET("/livesessions", liveSessionTempl(env))
		authedGroup.GET("/users", userTempl(env))
		authedGroup.GET("/authrules", authRuleTempl(env))
		authedGroup.GET("/noaccess", noaccessTempl(env))
		authedGroup.GET("/otp", otpTempl(env))
		authedGroup.GET("/setupotp", setupOtpTempl(env))

		apiGroup := authedGroup.Group("/api")
		{
			apiGroup.GET("/livesessions", liveSession(env))
			userGroup := apiGroup.Group("/users")
			{
				userGroup.GET("", user(env))
				userGroup.POST("/:id", updateUser(env))
				userGroup.GET("/:id/keys", downloadKey(env))
			}

			authRulesGroup := apiGroup.Group("/authrules")
			{
				authRulesGroup.GET("", authRule(env))
				authRulesGroup.POST("/:id", updateAuthRule(env))
				authRulesGroup.GET("/:id/delete", deleteAuthRule(env))
			}

			wsGroup := apiGroup.Group("/ws")
			{
				wsGroup.GET("/livesessions/:id", liveSessionWS(env))
				wsGroup.GET("/livesessions/:id/:sid", liveSessionWS(env))
			}
			apiGroup.GET("/disconnect/:id", disconnectLiveSession(env))
			apiGroup.GET("/disconnect/:id/:sid", disconnectLiveSession(env))
			apiGroup.GET("/sessions", session(env))
			apiGroup.GET("/sessions/:id", sessionID(env))

			apiGroup.POST("/otp", checkOtp(env))
			apiGroup.GET("/setupotp", setupotp(env))
		}
	}

	env.Green.Println("Running HTTP server at:", addr)

	env.Red.Fatal(r.Run(addr))
}

func ginifyHandlerFunc(h http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		h(c.Writer, c.Request)
	}
}

func ginifyHandler(h http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}

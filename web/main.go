package web

import (
	"encoding/gob"
	"net/http"
	"runtime"

	"github.com/gin-contrib/static"

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
	r.Use(static.Serve("/", static.LocalFile("web/static", false)))
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
		authedGroup.GET("/logout", Logout(env))
		authedGroup.GET("/sessions", SessionTempl(env))
		authedGroup.GET("/livesessions", LiveSessionTempl(env))
		authedGroup.GET("/users", UserTempl(env))
		authedGroup.GET("/authrules", AuthRuleTempl(env))
		authedGroup.GET("/noaccess", NoaccessTempl(env))
		authedGroup.GET("/otp", OtpTempl(env))
		authedGroup.GET("/setupotp", SetupOtpTempl(env))

		apiGroup := authedGroup.Group("/api")
		{
			apiGroup.GET("/livesessions", LiveSession(env))
			userGroup := apiGroup.Group("/users")
			{
				userGroup.GET("", User(env))
				userGroup.POST("/:id", UpdateUser(env))
				userGroup.GET("/:id/keys", DownloadKey(env))
			}

			authRulesGroup := apiGroup.Group("/authrules")
			{
				authRulesGroup.GET("", AuthRule(env))
				authRulesGroup.POST("/:id", UpdateAuthRule(env))
				authRulesGroup.GET("/:id/delete", DeleteAuthRule(env))
			}

			wsGroup := apiGroup.Group("/ws")
			{
				wsGroup.GET("/livesessions/:id", LiveSessionWS(env))
				wsGroup.GET("/livesessions/:id/:sid", LiveSessionWS(env))
			}
			apiGroup.GET("/disconnect/:id", DisconnectLiveSession(env))
			apiGroup.GET("/disconnect/:id/:sid", DisconnectLiveSession(env))
			apiGroup.GET("/sessions", session(env))
			apiGroup.GET("/sessions/:id", SessionID(env))

			apiGroup.POST("/otp", CheckOtp(env))
			apiGroup.GET("/setupotp", SetupOtp(env))
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

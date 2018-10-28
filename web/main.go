package web

import (
	"encoding/gob"
	"net/http"

	"github.com/gin-contrib/pprof"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/notion/trove_ssh_bastion/config"
	"golang.org/x/oauth2"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	store = cookie.NewStore([]byte("test"))
)

// Serve Starts the web server and all of its handlers
func Serve(addr string, env *config.Env) {
	oauthConfig := oauth2.Config{}
	env.Vconfig.SetDefault("OauthCredentials", &oauthConfig)
	env.Vconfig.UnmarshalKey("OauthCredentials", &oauthConfig)

	store.Options(sessions.Options{
		MaxAge: 1 * 60 * 60,
	})

	gob.Register(&oauth2.Token{})
	gob.Register(&config.User{})

	r := gin.Default()
	r.Use(sessions.Sessions("session", store))
	r.LoadHTMLGlob("web/templates/*")
	pprof.Register(r, nil)

	authedGroup := r.Group("/", authMiddleware(env))
	{
		authedGroup.GET("", index(env, oauthConfig))
		authedGroup.GET("/logout", logout(env))
		authedGroup.GET("/sessions", sessionTempl(env))
		authedGroup.GET("/livesessions", liveSessionTempl(env))
		authedGroup.GET("/users", userTempl(env))
		authedGroup.GET("/noaccess", noaccessTempl(env))

		apiGroup := authedGroup.Group("/api")
		{
			apiGroup.GET("/livesessions", liveSession(env))
			userGroup := apiGroup.Group("/users")
			{
				userGroup.GET("", user(env))
				userGroup.POST("/:id", updateUser(env))
				userGroup.GET("/:id/keys", downloadKey(env))
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
		}
	}

	r.GET("/api/opensessions", openSessions(env))

	env.Green.Println("Running HTTP server at:", addr)

	env.Red.Fatal(r.Run(addr))
}

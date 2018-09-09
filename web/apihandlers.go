package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/websocket"
	"github.com/notion/trove_ssh_bastion/config"
	"github.com/notion/trove_ssh_bastion/ssh"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	cryptossh "golang.org/x/crypto/ssh"
	"time"
)

func index(env *config.Env, conf oauth2.Config) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")

		session, err := store.Get(r, "session")
		if err != nil {
			env.Red.Println("Can't get session from request", err)
		}

		if code == "" {
			if k, ok := session.Values["loggedin"]; ok {
				if k.(bool) {
					http.Redirect(w, r, "/sessions", http.StatusFound)
					return
				}
			}

			state := sha256.Sum256(securecookie.GenerateRandomKey(32))

			session.Values["state"] = base64.URLEncoding.EncodeToString(state[:])
			err = session.Save(r, w)
			if err != nil {
				env.Red.Println("Error saving session:", err)
			}

			http.Redirect(w, r, conf.AuthCodeURL(session.Values["state"].(string)), http.StatusFound)
			return
		} else {
			if r.URL.Query().Get("state") == session.Values["state"] {
				token, err := conf.Exchange(context.TODO(), code)
				if err != nil {
					env.Red.Println("ISSUE EXCHANGING CODE:", err)
				}

				client := conf.Client(context.TODO(), token)

				resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
				if err != nil {
					env.Red.Println("ERROR GETTING USER INFO", err)
				}
				defer resp.Body.Close()

				userData := make(map[string]interface{})

				data, _ := ioutil.ReadAll(resp.Body)

				err = json.Unmarshal(data, &userData)
				if err != nil {
					env.Red.Println("Unable to unmarshal user info from google", err)
				}

				var user config.User

				env.DB.First(&user, "email = ?", userData["email"].(string))

				user.Email = userData["email"].(string)
				user.AuthToken = token.AccessToken

				session.Values["user"] = user
				session.Values["auth"] = token
				session.Values["loggedin"] = true
				err = session.Save(r, w)
				if err != nil {
					env.Red.Println("Error saving session:", err)
				}

				env.DB.Save(&user)

				http.Redirect(w, r, "/sessions", http.StatusFound)
				return
			} else {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
	}
}

func session(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionsData := make([]*config.Session, 0)

		ctx := context.Background()
		objectsIterator := env.LogsBucket.Objects(ctx, nil)

		var iteratorError error

		for iteratorError == nil {
			var dbSession config.Session
			var dbUser config.User

			object, err := objectsIterator.Next()

			if err != nil {
				iteratorError = err
				break
			}

			env.DB.Select([]string{"user_id", "time", "name", "host"}).First(&dbSession, "name = ?", object.Name).Select([]string{"email"}).Related(&dbUser, "UserID")

			dbSession.User = &dbUser

			sessionsData = append(sessionsData, &dbSession)
		}

		retData := make(map[string]interface{})

		retData["status"] = "ok"
		retData["sessions"] = sessionsData

		returnJson(w, r, retData, 0)
	}
}

func sessionId(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		ctx := context.Background()

		reader, err := env.LogsBucket.Object(vars["id"]).ReadCompressed(true).NewReader(ctx)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Transfer-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			io.Copy(w, reader)
		}
	}
}


func liveSession(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		retData := make(map[string]interface{})

		var newSessions []interface{}
		for k, client := range env.SshProxyClients {
			if client.SshServerClient.User != nil {
				sessionData := make(map[string]interface{})
				sessionData["Name"] = k
				sessionData["Host"] = client.SshServerClient.ProxyTo
				sessionData["User"] = client.SshServerClient.User.Email
				newSessions = append(newSessions, sessionData)
			}
		}

		retData["status"] = "ok"
		retData["livesessions"] = newSessions

		jsonData, err := json.Marshal(retData)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)
	}
}

func liveSessionWS(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		pathKey := vars["id"]

		c, err := upgrader.Upgrade(w, r, nil)

		env.Blue.Println("New WebSocket Connection From:", r.RemoteAddr)
		env.Blue.Println("Path:", pathKey)

		if err != nil {
			env.Red.Println("Upgrade error:", err)
			return
		}

		if proxyClient, ok := env.SshProxyClients[pathKey]; ok {
			if _, ok := env.WebsocketClients[pathKey]; !ok {
				env.WebsocketClients[pathKey] = make(map[string]*config.WsClient)
			}

			env.WebsocketClients[pathKey][c.RemoteAddr().String()] = &config.WsClient{
				Client: c,
			}

			wsWriter, err := c.NextWriter(websocket.TextMessage)
			if err != nil {
				env.Red.Println("Error establishing ws writer in playback")
			}

			for _, frame := range proxyClient.Closer.Cast.Frames {
				wsWriter.Write([]byte(frame.Data))
			}

			wsWriter.Close()
		} else {
			c.Close()
			return
		}

		for {
			_, p, err := c.ReadMessage()
			if err != nil {
				env.Red.Println("wsReader error:", err)

				break
			}

			if _, ok := env.SshProxyClients[pathKey]; ok {
				sshProxyClient := *env.SshProxyClients[pathKey].SshShellSession

				if sshProxyClient != nil {
					_, err = sshProxyClient.Write(p)
					if err != nil {
						env.Red.Println("SSH Session Write Error:", err)

						break
					}
				}
			}
		}

		defer func() {
			c.Close()
			delete(env.WebsocketClients[pathKey], c.RemoteAddr().String())

			env.Magenta.Println("Closed WebSocket Connection From:", r.RemoteAddr)
		}()
	}
}

func user(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		retData := make(map[string]interface{})
		var users []config.User

		env.DB.Find(&users)

		retData["status"] = "ok"
		retData["users"] = users

		returnJson(w, r, retData, 0)
	}
}

func userCerts(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		retData := make(map[string]interface{})
		var user config.User

		env.DB.Find(&user, vars["user_id"])
		r.ParseForm()

		signer := ssh.ParsePrivateKey(env.Config.UserPrivateKey, env.PKPassphrase, env)

		duration, err := time.ParseDuration(env.Config.Expires)
		if err != nil {
			env.Red.Println("Unable to parse duration to expire:", err)
		}

		casigner := ssh.NewCASigner(signer, duration, []string{}, []string{})

		cert, PK, err := casigner.Sign(env, user.Email, nil)
		if err != nil {
			env.Red.Println("Unable to sign PrivateKey:", err)
		}

		marshaled := cryptossh.MarshalAuthorizedKey(cert)

		user.Cert = marshaled[:len(marshaled)-1]
		user.PrivateKey = PK

		env.DB.Save(&user)

		retData["status"] = "ok"
		retData["user"] = user

		returnJson(w, r, retData, 0)
	}
}

func updateUser(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			http.Redirect(w, r, "/users", http.StatusFound)
			return
		}

		vars := mux.Vars(r)
		retData := make(map[string]interface{})
		var user config.User

		env.DB.Find(&user, vars["id"])
		r.ParseForm()

		decoded, err := base64.StdEncoding.DecodeString(r.Form.Get("privatekey"))
		if err != nil {
			env.Red.Println("Error base64 decoding string.", err)
		}

		user.Email = r.Form.Get("email")
		user.PrivateKey = decoded
		user.Authorized = r.Form.Get("authorized") == "on"

		env.DB.Save(&user)

		retData["status"] = "ok"
		retData["user"] = user

		returnJson(w, r, retData, 0)
	}
}
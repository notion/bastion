package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/websocket"
	"github.com/notion/trove_ssh_bastion/config"
	"github.com/notion/trove_ssh_bastion/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

var signer cryptossh.Signer
var casigner *ssh.CASigner

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
				var userCount int

				env.DB.Table("users").Count(&userCount)
				env.DB.First(&user, "email = ?", userData["email"].(string))

				if userCount == 0 {
					user.Admin = true
				}

				user.Email = userData["email"].(string)
				user.AuthToken = token.AccessToken
				env.DB.Save(&user)

				if user.Cert != nil {
					user.Cert = []byte{}
					user.PrivateKey = []byte{}
				}

				session.Values["user"] = user
				session.Values["loggedin"] = true
				err = session.Save(r, w)
				if err != nil {
					env.Red.Println("Error saving session:", err)
				}

				http.Redirect(w, r, "/sessions", http.StatusFound)
				return
			} else {
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
	}
}

func logout(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "session")
		if err != nil {
			env.Red.Println("Can't get session from request", err)
		}

		session.Values = make(map[interface{}]interface{})
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
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
			if client.SshServerClient.User != nil && len(client.SshShellSessions) > 0 {
				sessionData := make(map[string]interface{})
				sessionData["Name"] = k
				sessionData["Host"] = client.SshServerClient.ProxyTo
				sessionData["User"] = client.SshServerClient.User.Email
				sessionData["Sessions"] = len(client.SshShellSessions)
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

func openSessions(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		retData := make(map[string]interface{})

		var newSessions []interface{}
		for k, v := range env.SshProxyClients {
			sessionData := make(map[string]interface{})
			allChans := make([]map[string]interface{}, 0)
			sessionData["name"] = k

			for _, v2 := range v.SshChans {
				chanData := make(map[string]interface{})
				chanData["reqs"] = v2.Reqs
				chanData["data"] = v2.ChannelData
				chanData["type"] = v2.ChannelType
				allChans = append(allChans, chanData)
			}

			sessionData["chans"] = allChans

			newSessions = append(newSessions, sessionData)
		}

		retData["status"] = "ok"
		retData["livesessions"] = newSessions

		returnJson(w, r, retData, http.StatusOK)
	}
}

func liveSessionWS(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		pathKey, ok := vars["id"]
		if !ok {
			returnErr(w, r, errors.New("can't find id"), http.StatusInternalServerError)
			return
		}
		sidKey, ok := vars["sid"]
		if !ok {
			sidKey = ""
		}

		c, err := upgrader.Upgrade(w, r, nil)

		env.Blue.Println("New WebSocket Connection From:", r.RemoteAddr)
		env.Blue.Println("Path:", pathKey, sidKey)

		if err != nil {
			env.Red.Println("Upgrade error:", err)
			return
		}

		if proxyClient, ok := env.SshProxyClients[pathKey]; ok {
			place := 0
			if sidKey != "" {
				place, err = strconv.Atoi(sidKey)
			}

			if place < len(proxyClient.SshShellSessions) {
				if _, ok := env.WebsocketClients[pathKey+sidKey]; !ok {
					env.WebsocketClients[pathKey+sidKey] = make(map[string]*config.WsClient)
				}

				chanInfo := proxyClient.SshShellSessions[place]

				env.WebsocketClients[pathKey+sidKey][c.RemoteAddr().String()] = &config.WsClient{
					Client: c,
				}

				wsWriter, err := c.NextWriter(websocket.TextMessage)
				if err != nil {
					env.Red.Println("Error establishing ws writer in playback")
				}

				for _, frame := range chanInfo.Closer.Cast.Frames {
					wsWriter.Write([]byte(frame.Data))
				}

				wsWriter.Close()
			} else {
				return
			}

		} else {
			return
		}

		for {
			_, p, err := c.ReadMessage()
			if err != nil {
				env.Red.Println("wsReader error:", err)
				break
			}

			if _, ok := env.SshProxyClients[pathKey]; ok {
				place := 0
				if sidKey != "" {
					place, err = strconv.Atoi(sidKey)
				}

				if place < len(env.SshProxyClients[pathKey].SshShellSessions) {
					sshProxyClient := *env.SshProxyClients[pathKey].SshShellSessions[place].ProxyChan

					if sshProxyClient != nil {
						_, err = sshProxyClient.Write(p)
						if err != nil {
							env.Red.Println("SSH Session Write Error:", err)
							break
						}
					}
				} else {
					return
				}
			}
		}

		defer func() {
			c.Close()
			delete(env.WebsocketClients[pathKey+sidKey], c.RemoteAddr().String())

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

func updateUser(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Redirect(w, r, "/users", http.StatusFound)
			return
		}

		vars := mux.Vars(r)
		retData := make(map[string]interface{})
		var user config.User

		env.DB.Find(&user, vars["id"])
		r.ParseForm()

		user.Email = r.Form.Get("email")
		user.Authorized = r.Form.Get("authorized") == "on"
		user.UnixUser = r.Form.Get("unixuser")

		if user.Authorized && user.Cert == nil || r.Form.Get("override") == "on" {
			if signer == nil {
				signer = ssh.ParsePrivateKey(env.Config.UserPrivateKey, env.PKPassphrase, env)
			}

			if casigner == nil {
				duration, err := time.ParseDuration(env.Config.Expires)
				if err != nil {
					env.Red.Println("Unable to parse duration to expire:", err)
				}

				casigner = ssh.NewCASigner(signer, duration, []string{}, []string{})
			}

			cert, PK, err := casigner.Sign(env, user.Email, nil)
			if err != nil {
				env.Red.Println("Unable to sign PrivateKey:", err)
			}

			marshaled := cryptossh.MarshalAuthorizedKey(cert)

			user.Cert = marshaled
			user.CertExpires = time.Unix(int64(cert.ValidBefore), 0)
			user.PrivateKey = PK
		}

		env.DB.Save(&user)

		retData["status"] = "ok"
		retData["user"] = user

		returnJson(w, r, retData, 0)
	}
}

func downloadKey(env *config.Env) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Redirect(w, r, "/users", http.StatusFound)
			return
		}

		session, err := store.Get(r, "session")
		if err != nil {
			env.Red.Println("Can't get session from request", err)
		}

		sessionUser := session.Values["user"].(*config.User)

		vars := mux.Vars(r)
		var user config.User

		if env.DB.Find(&user, vars["id"]).RecordNotFound() || user.Cert == nil || (!sessionUser.Admin && sessionUser.ID != user.ID) {
			http.Redirect(w, r, "/users", http.StatusFound)
			return
		}

		if user.Authorized {
			if signer == nil {
				signer = ssh.ParsePrivateKey(env.Config.UserPrivateKey, env.PKPassphrase, env)
			}

			if casigner == nil {
				duration, err := time.ParseDuration(env.Config.Expires)
				if err != nil {
					env.Red.Println("Unable to parse duration to expire:", err)
				}

				casigner = ssh.NewCASigner(signer, duration, []string{}, []string{})
			}

			if user.Cert != nil && user.CertExpires.Before(time.Now()) {
				cert, PK, err := casigner.Sign(env, user.Email, nil)
				if err != nil {
					env.Red.Println("Unable to sign PrivateKey:", err)
				}

				marshaled := cryptossh.MarshalAuthorizedKey(cert)

				user.Cert = marshaled
				user.CertExpires = time.Unix(int64(cert.ValidBefore), 0)
				user.PrivateKey = PK

				env.DB.Save(&user)
			}
		}

		buf := new(bytes.Buffer)
		writer := zip.NewWriter(buf)

		for _, v := range []string{"id_rsa", "id_rsa.pub", "id_rsa-cert.pub"} {
			var fileData []byte
			switch v {
			case "id_rsa":
				fileData = user.PrivateKey
				break
			case "id_rsa.pub":
				pk := ssh.ParsePrivateKey(user.PrivateKey, "", env)
				fileData = cryptossh.MarshalAuthorizedKey(pk.PublicKey())
				break
			case "id_rsa-cert.pub":
				fileData = user.Cert
				break
			}

			fileHeader := &zip.FileHeader{
				Name:               v,
				UncompressedSize64: uint64(len(fileData)),
				Modified:           time.Now(),
				Method:             zip.Deflate,
			}

			fileHeader.SetMode(0600)

			fileWriter, err := writer.CreateHeader(fileHeader)
			if err != nil {
				env.Red.Println("Unable to write file to zip:", err)
			}

			fileWriter.Write(fileData)
		}

		writer.Close()

		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"authorization.zip\""))
		w.Write(buf.Bytes())
	}
}

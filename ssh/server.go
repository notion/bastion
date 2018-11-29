package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"

	"github.com/notion/bastion/proxyprotocol"

	"github.com/notion/bastion/config"
	"golang.org/x/crypto/ssh"
)

func startServer(addr string, proxyAddr string, env *config.Env) {
	signer := ParsePrivateKey(env.Config.PrivateKey, env.PKPassphrase, env)

	sshConfig := getSSHServerConfig(env, signer)

	sshConfig.AddHostKey(signer)

	env.Blue.Println("Added RSA Keypair to SSH Server")

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		env.Red.Fatal(err)
	}

	env.Green.Println("Running SSH server at:", addr)

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			env.Red.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}

		var proxConn net.Conn
		if env.Vconfig.GetBool("gce.lb.proxyproto.enabled") {
			proxConn = proxyprotocol.ParseConn(tcpConn)
		} else {
			proxConn = tcpConn
		}

		SSHConn, chans, reqs, err := ssh.NewServerConn(proxConn, sshConfig)
		if err != nil {
			env.Red.Printf("Failed to handshake (%s)", err)
			continue
		}

		client, _ := env.SSHServerClients.Load(SSHConn.RemoteAddr().String())
		SSHClient := client.(*config.SSHServerClient)

		SSHClient.Client = SSHConn

		env.Green.Printf("New SSH connection from %s (%s)", SSHConn.RemoteAddr(), SSHConn.ClientVersion())

		go ssh.DiscardRequests(reqs)
		go handleChannels(chans, SSHConn, proxyAddr, env)
	}
}

func handleChannels(chans <-chan ssh.NewChannel, SSHConn *ssh.ServerConn, proxyAddr string, env *config.Env) {
	for newChannel := range chans {
		go handleChannel(newChannel, SSHConn, proxyAddr, env)
	}
}

func handleChannel(newChannel ssh.NewChannel, SSHConn *ssh.ServerConn, proxyAddr string, env *config.Env) {
	switch channel := newChannel.ChannelType(); channel {
	case "session":
		handleSession(newChannel, SSHConn, proxyAddr, env)
	default:
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", channel))
	}
}

func handleSession(newChannel ssh.NewChannel, SSHConn *ssh.ServerConn, proxyAddr string, env *config.Env) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		env.Red.Printf("Could not accept channel (%s)", err)
		return
	}

	closeConn := func(rawConn net.Conn) {
		connection.Close()

		if rawConn != nil {
			rawConn.Close()
			env.SSHProxyClients.Delete(rawConn.RemoteAddr().String())
		}

		env.SSHServerClients.Delete(SSHConn.RemoteAddr().String())
		env.Magenta.Printf("Session closed")
	}

	go func() {
		for req := range requests {
			switch req.Type {
			case "subsystem":
				subsys := string(req.Payload[4:])

				if strings.HasPrefix(subsys, "proxy:") {
					req.Reply(true, nil)

					host := strings.Replace(subsys, "proxy:", "", 1)

					if serverClientInterface, ok := env.SSHServerClients.Load(SSHConn.RemoteAddr().String()); ok {
						serverClient := serverClientInterface.(*config.SSHServerClient)

						if serverClient.User.AuthorizedHosts != "" {
							regexMatch, err := regexp.MatchString(serverClient.User.AuthorizedHosts, host)
							if err != nil {
								env.Red.Println("Unable to match regex for host:", err)
							}

							if !regexMatch {
								closeConn(nil)
								return
							}
						} else {
							closeConn(nil)
							return
						}

						serverClient.Username = SSHConn.User()
						serverClient.ProxyTo = host

						rawProxyConn, err := net.Dial("tcp", proxyAddr)
						if err != nil {
							env.Red.Println("Unable to establish connection to TCP Socket:", err)
							closeConn(rawProxyConn)
							return
						}

						env.SSHProxyClients.Store(rawProxyConn.LocalAddr().String(), &config.SSHProxyClient{
							Client:           rawProxyConn,
							SSHServerClient:  serverClient,
							SSHChans:         make([]*config.ConnChan, 0),
							SSHShellSessions: make([]*config.ConnChan, 0),
							Mutex:            &sync.Mutex{},
						})

						var once sync.Once
						go func() {
							io.Copy(connection, rawProxyConn)
							once.Do(func() {
								closeConn(rawProxyConn)
							})
						}()
						go func() {
							io.Copy(rawProxyConn, connection)
							once.Do(func() {
								closeConn(rawProxyConn)
							})
						}()
					} else {
						env.Red.Println("Unable to find ssh server client.")
					}
				}
			default:
				env.Yellow.Println("UNKNOWN TYPE", req.Type)
			}
		}
	}()
}

func getSSHServerConfig(env *config.Env, signer ssh.Signer) *ssh.ServerConfig {
	userSigner := ParsePrivateKey(env.Config.UserPrivateKey, env.PKPassphrase, env)

	return &ssh.ServerConfig{
		NoClientAuth: false,
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			env.Yellow.Printf("Login attempt: %s, user %s key: %s", c.RemoteAddr(), c.User(), key)

			certcheck := &ssh.CertChecker{
				IsUserAuthority: func(auth ssh.PublicKey) bool {
					return bytes.Equal(auth.Marshal(), userSigner.PublicKey().Marshal())
				},
			}

			perms, err := certcheck.Authenticate(c, key)
			if err != nil {
				env.Red.Println("Unable to verify certificate:", err)
				return nil, errors.New("Unable to authenticate Key/Token")
			}

			keyData := ssh.MarshalAuthorizedKey(key)
			var sessionUser config.User

			if env.DB.First(&sessionUser, "cert = ?", keyData).RecordNotFound() {
				return nil, errors.New("user cannot be found")
			}

			if !sessionUser.Authorized {
				return nil, errors.New("user is not authorized")
			}

			env.SSHServerClients.Store(c.RemoteAddr().String(), &config.SSHServerClient{
				User: &sessionUser,
			})

			return perms, nil
		},
	}
}

package ssh

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/notion/bastion/proxyprotocol"
	// "github.com/notion/bastion/alertsystem"
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
			proxConn = proxyprotocol.ParseConn(tcpConn, env.Vconfig.GetBool("debug.ssh.enabled"))
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

						authed := false
						for _, v := range GetRegexMatches(serverClient.User) {
							if v == "" {
								continue
							}

							regexMatch, err := regexp.MatchString(v, host)
							if err != nil {
								env.Red.Println("Unable to match regex for host:", err)
								break
							}

							if regexMatch {
								authed = true
							}
						}

						if !authed {
							serverClient.Errors = append(serverClient.Errors, fmt.Errorf("You are not authorized to login to host: %s", host))
						}

						serverClient.Username = SSHConn.User()
						serverClient.ProxyTo = host

						rawProxyConn, err := net.Dial("tcp", proxyAddr)

						ipAddr := rawProxyConn.RemoteAddr().(*net.TCPAddr).IP
						var network net.IP
						if ipAddr.To4() != nil {
							mask := net.CIDRMask(24, 32)
							network = ipAddr.Mask(mask)
						} else {
							mask := net.CIDRMask(48, 128)
							network = ipAddr.Mask(mask)
						}

						alertInfo := &config.AlertInfo{
							User:       SSHConn.User(),
							IP:         network,
							Timestamp:  time.Now(),
							LoginType:  "ssh",
							Success:    true,
							FirstLogin: false,
							NewNetwork: false,
							BeenAWhile: false,
						}

						if !authed {
							alertInfo.Success = false
							env.AlertChannel <- *alertInfo
						} else {
							env.AlertChannel <- *alertInfo
						}

						if err != nil {
							env.Red.Println("Unable to establish connection to TCP Socket:", err)
							serverClient.Errors = append(serverClient.Errors, fmt.Errorf("Unable to establish remote TCP Socket: %s", err))
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
			sessionUser := &config.User{}

			clientConfig := &config.SSHServerClient{
				Errors: make([]error, 0),
				User:   sessionUser,
				Time:   time.Now(),
			}
			env.SSHServerClients.Store(c.RemoteAddr().String(), clientConfig)

			certcheck := &ssh.CertChecker{
				IsUserAuthority: func(auth ssh.PublicKey) bool {
					return bytes.Equal(auth.Marshal(), userSigner.PublicKey().Marshal())
				},
			}

			perms, err := certcheck.Authenticate(c, key)
			if err != nil {
				env.Red.Println("Unable to verify certificate:", err)
				clientConfig.Errors = append(clientConfig.Errors, fmt.Errorf("Unable to verify certificate: %s", err))

				if err.Error() == "ssh: normal key pairs not accepted" {
					return nil, err
				}

				return nil, nil
			}

			keyData := ssh.MarshalAuthorizedKey(key)

			if env.DB.Preload("AuthRules").First(&sessionUser, "cert = ?", keyData).RecordNotFound() {
				clientConfig.Errors = append(clientConfig.Errors, fmt.Errorf("Unable to find user"))
				return nil, nil
			}

			if !sessionUser.Authorized {
				clientConfig.Errors = append(clientConfig.Errors, fmt.Errorf("User is not authorized: %s", sessionUser.Email))
				return nil, nil
			}

			return perms, nil
		},
	}
}

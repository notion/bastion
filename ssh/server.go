package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/notion/trove_ssh_bastion/config"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"strings"
	"sync"
)

func startServer(addr string, proxyAddr string, env *config.Env) {
	signer := ParsePrivateKey(env.Config.PrivateKey, env.PKPassphrase, env)
	userSigner := ParsePrivateKey(env.Config.UserPrivateKey, env.PKPassphrase, env)

	sshConfig := &ssh.ServerConfig{
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
				return nil, errors.New("User cannot be found.")
			}

			if !sessionUser.Authorized {
				return nil, errors.New("User is not authorized.")
			}

			env.SshServerClients.Store(c.RemoteAddr().String(), &config.SshServerClient{
				User: &sessionUser,
			})

			return perms, nil
		},
	}

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

		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			env.Red.Printf("Failed to handshake (%s)", err)
			continue
		}

		client, _ := env.SshServerClients.Load(sshConn.RemoteAddr().String())
		sshClient := client.(*config.SshServerClient)

		sshClient.Client = sshConn

		env.Green.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

		go ssh.DiscardRequests(reqs)
		go handleChannels(chans, sshConn, proxyAddr, env)
	}
}

func handleChannels(chans <-chan ssh.NewChannel, sshConn *ssh.ServerConn, proxyAddr string, env *config.Env) {
	for newChannel := range chans {
		go handleChannel(newChannel, sshConn, proxyAddr, env)
	}
}

func handleChannel(newChannel ssh.NewChannel, sshConn *ssh.ServerConn, proxyAddr string, env *config.Env) {
	switch channel := newChannel.ChannelType(); channel {
	case "session":
		handleSession(newChannel, sshConn, proxyAddr, env)
	default:
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", channel))
	}
}

func handleSession(newChannel ssh.NewChannel, sshConn *ssh.ServerConn, proxyAddr string, env *config.Env) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		env.Red.Printf("Could not accept channel (%s)", err)
		return
	}

	closeConn := func(rawConn net.Conn) {
		connection.Close()
		rawConn.Close()

		env.SshServerClients.Delete(sshConn.RemoteAddr().String())
		env.SshProxyClients.Delete(rawConn.RemoteAddr().String())
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

					if serverClientInterface, ok := env.SshServerClients.Load(sshConn.RemoteAddr().String()); ok {
						serverClient := serverClientInterface.(*config.SshServerClient)
						serverClient.Username = sshConn.User()
						serverClient.ProxyTo = host

						rawProxyConn, err := net.Dial("tcp", proxyAddr)
						if err != nil {
							env.Red.Println("Unable to establish connection to TCP Socket:", err)
							closeConn(rawProxyConn)
							return
						}

						env.SshProxyClients.Store(rawProxyConn.LocalAddr().String(), &config.SshProxyClient{
							Client:           rawProxyConn,
							SshServerClient:  serverClient,
							SshChans:         make([]*config.ConnChan, 0),
							SshShellSessions: make([]*config.ConnChan, 0),
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

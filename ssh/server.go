package ssh

import (
	"fmt"
	"github.com/notion/trove_ssh_bastion/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

func startServer(addr string, proxyAddr string, env *config.Env) {
	sshConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	var pkBytes []byte

	if len(env.Config.PrivateKey) == 0 {
		pkBytes = createPrivateKey(env)
	} else {
		pkBytes = env.Config.PrivateKey
	}

	signer, err := ssh.ParsePrivateKey(pkBytes)
	if err != nil {
		log.Fatal(env.Red.Sprint(err))
	}

	env.Blue.Println("Parsed RSA Keypair")

	sshConfig.AddHostKey(signer)

	env.Blue.Println("Added RSA Keypair to SSH Server")

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(env.Red.Sprint(err))
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

		env.SshServerClients[sshConn.RemoteAddr().String()] = &config.SshServerClient{
			Client: sshConn,
		}

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

	closeConn := func() {
		connection.Close()

		delete(env.SshServerClients, sshConn.RemoteAddr().String())
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

					if _, ok := env.SshServerClients[sshConn.RemoteAddr().String()]; ok {
						env.SshServerClients[sshConn.RemoteAddr().String()].Username = sshConn.User()
						env.SshServerClients[sshConn.RemoteAddr().String()].ProxyTo = host

						rawProxyConn, err := net.Dial("unix", proxyAddr)
						if err != nil {
							env.Red.Println("SOMETHING IS BORKED DUD")
							closeConn()
							return
						}

						env.SshProxyClients[rawProxyConn.LocalAddr().String()] = &config.SshProxyClient{
							Client:          rawProxyConn,
							SshServerClient: env.SshServerClients[sshConn.RemoteAddr().String()],
						}

						var once sync.Once
						go func() {
							io.Copy(connection, rawProxyConn)
							once.Do(closeConn)
						}()
						go func() {
							io.Copy(rawProxyConn, connection)
							once.Do(closeConn)
						}()
					} else {
						env.Red.Println("SOMETHING WENT WRONG")
					}
				}
			case "auth-agent-req@openssh.com":
				agentChan, agentReq, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
				if err != nil {
					env.Red.Println("Can't open agent channel")
				}

				go ssh.DiscardRequests(agentReq)

				loadedAgent := agent.NewClient(agentChan)
				env.SshServerClients[sshConn.RemoteAddr().String()].Agent = &loadedAgent

				keys, err := loadedAgent.List()
				if err != nil {
					env.Red.Println("Error loading key list from agent", err)
				}

				if len(keys) > 0 {
					env.SshServerClients[sshConn.RemoteAddr().String()].PublicKey = keys[0]

					var sessionUser config.User

					env.DB.First(&sessionUser, "private_key = ?", keys[0].Blob)

					env.Yellow.Println(&sessionUser)

					env.SshServerClients[sshConn.RemoteAddr().String()].User = &sessionUser
				}
			default:
				env.Yellow.Println("UNKNOWN TYPE", req.Type)
			}
		}
	}()
}

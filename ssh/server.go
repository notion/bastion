package ssh

import (
	"log"
	"sync"
	"io"
	"golang.org/x/crypto/ssh"
	"fmt"
	"github.com/fatih/color"
	"net"
	"github.com/notion/trove_ssh_bastion/config"
	"strconv"
	"strings"
	"golang.org/x/crypto/ssh/agent"
)

//var (
//	//command = "ssh"
//	//args = []string{"proc0.gce.us.nomail.net"}
//	//command = "bash"
//	//args = make([]string, 0)
//)

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func startServer(addr string, env *config.Env) {
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
		color.Set(color.FgRed)
		log.Fatal(err)
		color.Unset()
	}

	color.Set(color.FgBlue)
	log.Println("Parsed RSA Keypair")
	color.Unset()

	sshConfig.AddHostKey(signer)

	color.Set(color.FgBlue)
	log.Println("Added RSA Keypair to SSH Server")
	color.Unset()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		color.Set(color.FgRed)
		log.Fatal(err)
		color.Unset()
	}

	color.Set(color.FgGreen)
	log.Println("Running SSH server at:", addr)
	color.Unset()

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			color.Set(color.FgRed)
			log.Printf("Failed to accept incoming connection (%s)", err)
			color.Unset()
			continue
		}

		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			color.Set(color.FgRed)
			log.Printf("Failed to handshake (%s)", err)
			color.Unset()
			continue
		}

		env.SshServerClients[sshConn.RemoteAddr().String()] = &config.SshServerClient{
			Client: sshConn,
		}

		color.Set(color.FgGreen)
		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		color.Unset()

		go ssh.DiscardRequests(reqs)
		go handleChannels(chans, sshConn, env)
	}
}

func handleChannels(chans <-chan ssh.NewChannel, sshConn *ssh.ServerConn, env *config.Env) {
	for newChannel := range chans {
		go handleChannel(newChannel, sshConn, env)
	}
}

func handleChannel(newChannel ssh.NewChannel, sshConn *ssh.ServerConn, env *config.Env) {
	switch channel := newChannel.ChannelType(); channel {
	case "session":
		handleSession(newChannel, sshConn, env)
	case "direct-tcpip":
		handleProxy(newChannel, sshConn, env)
	default:
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", channel))
	}
}

func handleProxy(newChannel ssh.NewChannel, sshConn *ssh.ServerConn, env *config.Env) {
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	closeConn := func() {
		connection.Close()
		log.Printf("Proxy Session closed")
	}

	go func() {
		for req := range requests {
			fmt.Println(req.Type, req.WantReply, string(req.Payload))
		}
	}()

	var payload forwardedTCPPayload
	if err = ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		log.Println(err)
	}

	conn, err := net.Dial("tcp", payload.Addr + ":" + strconv.FormatUint(uint64(payload.Port), 10))
	if err != nil {
		log.Println(err)
	}

	var once sync.Once
	go func() {
		io.Copy(connection, conn)
		once.Do(closeConn)
	}()
	go func() {
		io.Copy(conn, connection)
		once.Do(closeConn)
	}()
}

func handleSession(newChannel ssh.NewChannel, sshConn *ssh.ServerConn, env *config.Env) {
	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	// Prepare teardown function
	closeConn := func() {
		connection.Close()

		delete(env.SshServerClients, sshConn.RemoteAddr().String())
		log.Printf("Session closed")
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "subsystem":
				subsys := string(req.Payload[4:])

				if strings.HasPrefix(subsys, "proxy:") {
					log.Println("PROXYING")
					req.Reply(true, nil)

					host := strings.Replace(subsys, "proxy:", "", 1)

					if _, ok := env.SshServerClients[sshConn.RemoteAddr().String()]; ok {
						env.SshServerClients[sshConn.RemoteAddr().String()].Username = sshConn.User()
						env.SshServerClients[sshConn.RemoteAddr().String()].ProxyTo = host


						rawProxyConn, err := net.Dial("tcp", "localhost:2223")
						if err != nil {
							log.Println("SOMETHING IS BORKED DUD" )
							closeConn()
							return
						}

						env.SshProxyClients[rawProxyConn.LocalAddr().String()] = &config.SshProxyClient{
							Client: rawProxyConn,
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
						log.Println("SOMETHING WENT WRONG")
					}
				}
			case "auth-agent-req@openssh.com":
				agentChan, agentReq, err := sshConn.OpenChannel("auth-agent@openssh.com", nil)
				if err != nil {
					log.Println("Can't open agent channel")
				}

				go ssh.DiscardRequests(agentReq)

				loadedAgent := agent.NewClient(agentChan)
				env.SshServerClients[sshConn.RemoteAddr().String()].Agent = &loadedAgent

				keys, err := loadedAgent.List()
				if err != nil {
					log.Println("Error loading key list from agent", err)
				}

				if len(keys) > 0 {
					env.SshServerClients[sshConn.RemoteAddr().String()].PublicKey = keys[0]

					var sessionUser config.User

					env.DB.First(&sessionUser, "private_key = ?", keys[0].Blob)

					log.Println(&sessionUser)

					env.SshServerClients[sshConn.RemoteAddr().String()].User = &sessionUser
				}
			default:
				log.Println("UNKNOWN TYPE", req.Type)
			}
		}
	}()
}
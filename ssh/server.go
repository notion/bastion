package ssh

import (
	"log"
	"github.com/kr/pty"
	"sync"
	"io"
	"golang.org/x/crypto/ssh"
	"fmt"
	"os/exec"
	"github.com/fatih/color"
	"net"
	"github.com/notion/trove_ssh_bastion/config"
	"strconv"
	"strings"
)

var (
	//command = "ssh"
	//args = []string{"proc0.gce.us.nomail.net"}
	command = "bash"
	args = make([]string, 0)
)

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

		//env.SshServerClients[sshConn.RemoteAddr()] = &config.SshServerClient{
		//	Client: sshConn,
		//}

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

	// Fire up bash for this session
	bash := exec.Command(command, args...)

	// Prepare teardown function
	closeConn := func() {
		connection.Close()
		_, err := bash.Process.Wait()
		if err != nil {
			log.Printf("Failed to exit bash (%s)", err)
		}

		delete(env.SshServerClients, sshConn.RemoteAddr())
		log.Printf("Session closed")
	}

	// Allocate a terminal for this channel
	log.Print("Creating pty...")
	bashf, err := pty.Start(bash)
	if err != nil {
		log.Printf("Could not start pty (%s)", err)
		closeConn()
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)

					//pipe session to bash and visa-versa
					var once sync.Once
					go func() {
						io.Copy(connection, bashf)
						once.Do(closeConn)
					}()
					go func() {
						io.Copy(bashf, connection)
						once.Do(closeConn)
					}()
				}
			case "pty-req":
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
			case "subsystem":
				subsys := string(req.Payload[4:])

				if strings.HasPrefix(subsys, "proxy:") {
					log.Println("PROXYING")
					req.Reply(true, nil)

					host := strings.Replace(subsys, "proxy:", "", 1)


				}
			default:
				log.Println("UNKNOWN TYPE", req.Type)
			}
		}
	}()
}
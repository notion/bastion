package ssh

import (
	"errors"
	"github.com/notion/trove_ssh_bastion/config"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"os/signal"
	"time"
)

func startProxyServer(addr string, env *config.Env) {
	signer := ParsePrivateKey(env.Config.PrivateKey, env.PKPassphrase, env)
	serverSigner := ParsePrivateKey(env.Config.ServerPrivateKey, env.PKPassphrase, env)

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: false,
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			env.Yellow.Printf("Login attempt: %s, user %s key: %s", c.RemoteAddr(), c.User(), key)

			if _, ok := env.SshProxyClients[c.RemoteAddr().String()]; ok {
				duration, err := time.ParseDuration("1m")
				if err != nil {
					env.Red.Println("Unable to parse duration to expire:", err)
				}

				casigner := NewCASigner(serverSigner, duration, []string{}, []string{})

				cert, PK, err := casigner.Sign(env, "root", nil)
				if err != nil {
					env.Red.Println("Unable to sign PK:", err)
				}

				signer = ParsePrivateKey(PK, env.PKPassphrase, env)

				certsigner, err := ssh.NewCertSigner(cert, signer)
				if err != nil {
					env.Red.Println("Error loading cert signer:", err)
				}

				clientConfig := &ssh.ClientConfig{
					HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
						return nil
					},
					User: "root",
					Auth: []ssh.AuthMethod{
						ssh.PublicKeys(certsigner),
					},
				}

				client, err := ssh.Dial("tcp", env.SshProxyClients[c.RemoteAddr().String()].SshServerClient.ProxyTo, clientConfig)
				if err != nil {
					env.Red.Println("Error in proxy authentication:", err)
					return nil, err
				}

				env.SshProxyClients[c.RemoteAddr().String()].SshClient = client

				return nil, err
			}

			return nil, errors.New("can't find initial proxy connection")
		},
	}

	sshConfig.AddHostKey(signer)

	env.Blue.Println("Added RSA Keypair to SSH Server")

	listener, err := net.Listen("unix", addr)
	if err != nil {
		env.Red.Fatal(err)
	}

	defer listener.Close()

	stopped := false
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			listener.Close()
			stopped = true
			return
		}
	}()

	env.Green.Println("Running SSH proxy server at:", addr)

	for !stopped {
		tcpConn, err := listener.Accept()
		if err != nil {
			env.Red.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}

		sshconn := &ProxyHandler{Conn: tcpConn, config: sshConfig, env: env}

		go func() {
			sshconn.Serve()

			delete(env.SshProxyClients, tcpConn.RemoteAddr().String())
			delete(env.WebsocketClients, tcpConn.RemoteAddr().String())
		}()

		env.Yellow.Printf("New connection from %s (%s)", tcpConn.RemoteAddr())
	}
}
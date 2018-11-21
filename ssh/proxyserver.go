package ssh

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/notion/bastion/config"
	"golang.org/x/crypto/ssh"
)

func startProxyServer(addr string, env *config.Env) {
	signer := ParsePrivateKey(env.Config.PrivateKey, env.PKPassphrase, env)
	sshConfig := getSSHProxyConfig(env, signer)

	sshConfig.AddHostKey(signer)

	env.Blue.Println("Added RSA Keypair to SSH Server")

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		env.Red.Fatal(err)
	}

	defer listener.Close()

	mutex := &sync.Mutex{}

	mutex.Lock()
	stopped := false
	mutex.Unlock()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		for range c {
			listener.Close()

			mutex.Lock()
			stopped = true
			mutex.Unlock()

			return
		}
	}()

	env.Green.Println("Running SSH proxy server at:", addr)

	isStopped := func() bool {
		mutex.Lock()
		defer mutex.Unlock()
		return !stopped
	}

	for isStopped() {
		tcpConn, err := listener.Accept()
		if err != nil {
			env.Red.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}

		SSHConn := &ProxyHandler{Conn: tcpConn, config: sshConfig, env: env}

		go func() {
			SSHConn.Serve()

			env.SSHProxyClients.Delete(tcpConn.RemoteAddr().String())
			env.WebsocketClients.Delete(tcpConn.RemoteAddr().String())
		}()

		env.Yellow.Printf("New connection from %s", tcpConn.RemoteAddr())
	}
}

func getSSHProxyConfig(env *config.Env, signer ssh.Signer) *ssh.ServerConfig {
	serverSigner := ParsePrivateKey(env.Config.ServerPrivateKey, env.PKPassphrase, env)

	return &ssh.ServerConfig{
		NoClientAuth: false,
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			env.Yellow.Printf("Login attempt: %s, user %s key: %s", c.RemoteAddr(), c.User(), key)

			if proxClient, ok := env.SSHProxyClients.Load(c.RemoteAddr().String()); ok {
				proxyClient := proxClient.(*config.SSHProxyClient)
				duration := time.Minute * 1
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

				client, err := ssh.Dial("tcp", proxyClient.SSHServerClient.ProxyTo, clientConfig)
				if err != nil {
					env.Red.Println("Error in proxy authentication:", err)
					return nil, err
				}

				session, _ := client.NewSession()
				defer session.Close()
				defer client.Close()

				var stdoutBuf bytes.Buffer
				session.Stdout = &stdoutBuf
				session.Run("hostname")

				if proxyClient.SSHServerClient.User.AuthorizedHosts != "" {
					regexMatch, err := regexp.MatchString(proxyClient.SSHServerClient.User.AuthorizedHosts, strings.TrimSpace(stdoutBuf.String()))
					if err != nil {
						env.Red.Println("Unable to match regex for host:", err)
					}

					proxyClient.SSHServerClient.ProxyToHostname = strings.TrimSpace(stdoutBuf.String())

					if !regexMatch {
						return nil, errors.New("no authorization for host")
					}
				} else {
					return nil, errors.New("user has no authorization for hosts")
				}

				realClient, err := ssh.Dial("tcp", proxyClient.SSHServerClient.ProxyTo, clientConfig)
				if err != nil {
					env.Red.Println("Error in proxy authentication:", err)
					return nil, err
				}

				proxyClient.SSHClient = realClient

				return nil, err
			}

			return nil, errors.New("can't find initial proxy connection")
		},
	}
}

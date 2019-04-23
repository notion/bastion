package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/notion/bastion/config"
	"golang.org/x/crypto/ssh"
)

func startProxyServer(addr string, env *config.Env) {
	signer := ParsePrivateKey(env.Config.PrivateKey, env.PKPassphrase, env)
	sshConfig := getSSHProxyConfig(env)

	sshConfig.AddHostKey(signer)

	env.Blue.Println("Added RSA Keypair to SSH Server")

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		env.Red.Fatal(err)
	}

	defer listener.Close()

	env.Green.Println("Running SSH proxy server at:", addr)

	for {
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

func getSSHProxyConfig(env *config.Env) *ssh.ServerConfig {
	serverSigner := ParsePrivateKey(env.Config.ServerPrivateKey, env.PKPassphrase, env)

	return &ssh.ServerConfig{
		NoClientAuth: false,
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			env.Yellow.Printf("Login attempt: %s, user %s key: %s", c.RemoteAddr(), c.User(), key)

			if proxClient, ok := env.SSHProxyClients.Load(c.RemoteAddr().String()); ok {
				proxyClient := proxClient.(*config.SSHProxyClient)

				if len(proxyClient.SSHServerClient.Errors) > 0 {
					return nil, nil
				}

				duration := time.Minute * 1
				casigner := NewCASigner(serverSigner, duration, []string{}, []string{})

				cert, PK, err := casigner.Sign(env, "root", nil)
				if err != nil {
					env.Red.Println("Unable to sign PK:", err)
				}

				newSigner := ParsePrivateKey(PK, env.PKPassphrase, env)

				certsigner, err := ssh.NewCertSigner(cert, newSigner)
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
					Timeout: 2 * time.Second,
				}

				rawProxyConn, err := net.DialTimeout("tcp", proxyClient.SSHServerClient.ProxyTo, clientConfig.Timeout)
				if err != nil {
					proxyClient.SSHServerClient.Errors = append(proxyClient.SSHServerClient.Errors, fmt.Errorf("Error in proxy authentication: %s", err))
					env.Red.Println("Error in proxy authentication:", err)
					return nil, nil
				}

				proxyConn, proxyChans, proxyReqs, err := ssh.NewClientConn(rawProxyConn, proxyClient.SSHServerClient.ProxyTo, clientConfig)
				if err != nil {
					proxyClient.SSHServerClient.Errors = append(proxyClient.SSHServerClient.Errors, fmt.Errorf("Error in proxy authentication: %s", err))
					env.Red.Println("Error in proxy authentication:", err)
					return nil, nil
				}

				fakeChan := make(chan ssh.NewChannel, 0)
				fakeReqs := make(chan *ssh.Request, 0)

				client := ssh.NewClient(proxyConn, fakeChan, fakeReqs)

				close(fakeChan)
				close(fakeReqs)

				session, _ := client.NewSession()
				defer session.Close()

				var stdoutBuf bytes.Buffer
				session.Stdout = &stdoutBuf
				session.Run("hostname")
				proxyClient.SSHServerClient.ProxyToHostname = strings.TrimSpace(stdoutBuf.String())

				authed := false
				for _, v := range GetRegexMatches(proxyClient.SSHServerClient.User) {
					if v == "" {
						continue
					}

					regexMatch, err := regexp.MatchString(v, proxyClient.SSHServerClient.ProxyToHostname)
					if err != nil {
						env.Red.Println("Unable to match regex for host:", err)
						break
					}

					if regexMatch {
						authed = true
					}
				}

				if !authed {
					defer client.Close()
					proxyClient.SSHServerClient.Errors = append(proxyClient.SSHServerClient.Errors, fmt.Errorf("You are not authorized to login to host: %s", proxyClient.SSHServerClient.ProxyToHostname))
					return nil, nil
				}

				proxyClient.SSHClient = client
				proxyClient.SSHConn = proxyConn
				proxyClient.SSHClientChans = proxyChans
				proxyClient.SSHClientReqs = proxyReqs

				return nil, err
			}

			return nil, errors.New("can't find initial proxy connection")
		},
	}
}

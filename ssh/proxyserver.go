package ssh

import (
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/notion/trove_ssh_bastion/config"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
)

func startProxyServer(addr string, env *config.Env) {
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

	sshConfig := &ssh.ServerConfig{
		NoClientAuth: false,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			fmt.Printf("Login attempt: %s, user %s password: %s", c.RemoteAddr(), c.User(), string(pass))

			if _, ok := env.SshProxyClients[c.RemoteAddr().String()]; ok {
				clientConfig := &ssh.ClientConfig{
					HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
						return nil
					},
					User: env.SshProxyClients[c.RemoteAddr().String()].SshServerClient.Username,
					Auth: []ssh.AuthMethod{
						ssh.Password(string(pass)),
					},
				}

				client, err := ssh.Dial("tcp", env.SshProxyClients[c.RemoteAddr().String()].SshServerClient.ProxyTo, clientConfig)
				if err != nil {
					log.Println("ERROR IN CALLBACKPW", err)
					return nil, err
				}

				env.SshProxyClients[c.RemoteAddr().String()].SshClient = client

				return nil, err
			}

			return nil, errors.New("can't find initial proxy connection")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fmt.Printf("Login attempt: %s, user %s key: %s", c.RemoteAddr(), c.User(), key)

			if _, ok := env.SshProxyClients[c.RemoteAddr().String()]; ok {
				var signers []ssh.Signer

				if env.SshProxyClients[c.RemoteAddr().String()].SshServerClient.Agent != nil {
					agent := *env.SshProxyClients[c.RemoteAddr().String()].SshServerClient.Agent

					signers, err = agent.Signers()
					if err != nil {
						log.Println("Error getting signers", err)
					}
				}

				if signers == nil {
					signers = []ssh.Signer{signer}
				}

				clientConfig := &ssh.ClientConfig{
					HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
						return nil
					},
					User: env.SshProxyClients[c.RemoteAddr().String()].SshServerClient.Username,
					Auth: []ssh.AuthMethod{
						ssh.PublicKeys(signers...),
					},
				}

				client, err := ssh.Dial("tcp", env.SshProxyClients[c.RemoteAddr().String()].SshServerClient.ProxyTo, clientConfig)
				if err != nil {
					log.Println("ERROR IN CALLBACKPK", err)
					return nil, err
				}

				env.SshProxyClients[c.RemoteAddr().String()].SshClient = client

				return nil, err
			}

			return nil, errors.New("can't find initial proxy connection")
		},
	}

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

	defer listener.Close()

	color.Set(color.FgGreen)
	log.Println("Running SSH proxy server at:", addr)
	color.Unset()

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			color.Set(color.FgRed)
			log.Printf("Failed to accept incoming connection (%s)", err)
			color.Unset()
			continue
		}

		sshconn := &SshConn{Conn: tcpConn, config: sshConfig, callbackFn: callbackFn(env), wrapFn: wrapFn(env), closeFn: closeFn(env), env: env}

		go func() {
			if err := sshconn.serve(); err != nil {
				color.Set(color.FgRed)
				log.Printf("Error occured while serving %s\n", err)
				color.Unset()
			}

			color.Set(color.FgRed)
			log.Println("Connection closed.")
			color.Unset()

			delete(env.SshProxyClients, tcpConn.RemoteAddr().String())
			delete(env.WebsocketClients, tcpConn.RemoteAddr().String())
		}()

		color.Set(color.FgGreen)
		log.Printf("New connection from %s (%s)", tcpConn.RemoteAddr())
		color.Unset()
	}
}

func callbackFn(env *config.Env) func(ssh.ConnMetadata) (*ssh.Client, error) {
	return func(c ssh.ConnMetadata) (*ssh.Client, error) {
		var err error
		meta, ok := env.SshProxyClients[c.RemoteAddr().String()]
		log.Println(meta, ok, env.SshProxyClients)
		if !ok {
			err = errors.New("Callback is bad.")
			return nil, err
		}

		fmt.Println(meta)

		client := meta.SshClient
		fmt.Printf("Connection accepted from: %s", c.RemoteAddr())

		return client, err
	}
}

func wrapFn(env *config.Env) func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error) {
	return func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error) {
		return config.NewAsciicastReadCloser(r, c, 80, 40, env), nil
	}
}

func closeFn(env *config.Env) func(c ssh.ConnMetadata) error {
	return func(c ssh.ConnMetadata) error {
		fmt.Println("Connection closed.")
		return nil
	}
}

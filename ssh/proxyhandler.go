package ssh

import (
	"github.com/notion/trove_ssh_bastion/config"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
)

type ProxyHandler struct {
	net.Conn
	config *ssh.ServerConfig
	env    *config.Env
}

func (p *ProxyHandler) Serve() {
	clientConn, clientChans, clientReqs, err := ssh.NewServerConn(p, p.config)
	if err != nil {
		p.env.Red.Println("Failed to process handshake", err)
		return
	}

	meta, ok := p.env.SshProxyClients[p.RemoteAddr().String()]
	if !ok {
		p.env.Red.Println("Unable to find SSH Client to connect to server connection.")
		return
	}

	proxyConn := meta.SshClient

	go ssh.DiscardRequests(clientReqs)

	for openedChannel := range clientChans {
		proxyChannel, proxyReqs, err := proxyConn.OpenChannel(openedChannel.ChannelType(), openedChannel.ExtraData())
		if err != nil {
			p.env.Red.Println("Couldn't accept channel on proxy:", err)
			return
		}

		clientChannel, clientReqs2, err := openedChannel.Accept()
		if err != nil {
			p.env.Red.Println("Couldn't accept channel on client:", err)
			return
		}

		closeConns := func() {
			clientConn.Close()
			proxyConn.Close()
		}

		go func() {

		r:
			for {
				var req *ssh.Request
				var dst ssh.Channel

				select {
				case req = <-clientReqs2:
					dst = proxyChannel
				case req = <-proxyReqs:
					dst = clientChannel
				}

				if req == nil || dst == nil {
					break r
				}

				b, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
				if err != nil {
					p.env.Red.Println("Error sending request through channel:", err)
				}

				if req.WantReply {
					req.Reply(b, nil)
				}

				if proxClient, ok := p.env.SshProxyClients[p.RemoteAddr().String()]; ok {
					proxClient.SshReqs[req.Type] = req.Payload
				}

				switch req.Type {
				case "exit-status":
					break r
				case "shell":
					if proxClient, ok := p.env.SshProxyClients[p.RemoteAddr().String()]; ok {
						proxClient.SshShellSession = &dst
					}
				}
			}

			proxyChannel.Close()
			clientChannel.Close()

			defer closeConns()
		}()

		var wrappedClientChannel io.ReadCloser = clientChannel
		var wrappedProxyChannel = config.NewAsciicastReadCloser(proxyChannel, clientConn, 80, 40, p.env)

		go io.Copy(clientChannel, wrappedProxyChannel)
		go io.Copy(proxyChannel, wrappedClientChannel)

		closeChans := func() {
			wrappedClientChannel.Close()
			wrappedProxyChannel.Close()
		}

		defer closeChans()
		defer closeConns()
	}

	p.env.Magenta.Println("Closed proxy connection.")
}

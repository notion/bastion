package ssh

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/notion/bastion/config"
	"golang.org/x/crypto/ssh"
)

// ProxyHandler is the base handler for an SSH Connection and Proxy
type ProxyHandler struct {
	net.Conn
	config *ssh.ServerConfig
	env    *config.Env
}

// Serve handles the proxy
func (p *ProxyHandler) Serve() {
	clientConn, clientChans, clientReqs, err := ssh.NewServerConn(p, p.config)
	if err != nil {
		p.env.Red.Println("Failed to process handshake", err)
		return
	}

	metaInterface, ok := p.env.SSHProxyClients.Load(p.RemoteAddr().String())
	meta := metaInterface.(*config.SSHProxyClient)
	if !ok {
		p.env.Red.Println("Unable to find SSH Client to connect to server connection.")
		return
	}

	stopped := false

	proxyConn := meta.SSHClient

	go ssh.DiscardRequests(clientReqs)

	go func() {
		for openedChannel := range meta.SSHClientChans {
			if stopped {
				break
			}

			proxyChannel, proxyReqs, err := openedChannel.Accept()
			if err != nil {
				p.env.Red.Println("Couldn't accept channel on proxy:", err)
				return
			}

			clientChannel, clientReqs2, err := clientConn.OpenChannel(openedChannel.ChannelType(), openedChannel.ExtraData())
			if err != nil {
				p.env.Red.Println("Couldn't accept channel on proxy:", err)
				return
			}

			closeParentChans := func() {
				proxyChannel.Close()
				clientChannel.Close()
			}

			go func() {
				for {
					var req *ssh.Request
					var dst ssh.Channel
					var reqFrom string
					var dstTo string

					select {
					case req = <-clientReqs2:
						dst = proxyChannel
						reqFrom = "client"
						dstTo = "proxy"
					case req = <-proxyReqs:
						dst = clientChannel
						reqFrom = "proxy"
						dstTo = "client"
					}

					if req == nil || dst == nil {
						break
					}

					b, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
					if err != nil {
						p.env.Red.Println("Error sending request through channel:", err)
					}

					if req.WantReply {
						req.Reply(b, nil)
					}

					if stopped {
						break
					}
				}

				timer := time.NewTimer(1 * time.Second)
				<-timer.C
				closeParentChans()
			}()

			chanInfo := &config.ConnChan{
				ChannelType: openedChannel.ChannelType(),
				ChannelData: openedChannel.ExtraData(),
				Reqs:        make([]*config.ConnReq, 0),
				ClientConn:  clientConn,
				ProxyConn:   proxyConn,
				ProxyChan:   &proxyChannel,
				ClientChan:  &clientChannel,
			}

			var wrappedClientChannel io.ReadCloser = clientChannel
			var wrappedProxyChannel = config.NewAsciicastReadCloser(proxyChannel, clientConn, 80, 40, chanInfo, p.env)

			closeChans := func() {
				wrappedClientChannel.Close()
				wrappedProxyChannel.Close()

				closeParentChans()
			}

			allClose := func() {
				closeChans()
			}

			var once sync.Once
			go func() {
				io.Copy(clientChannel, wrappedProxyChannel)
				timer := time.NewTimer(1 * time.Second)
				<-timer.C
				once.Do(allClose)
			}()
			go func() {
				io.Copy(proxyChannel, wrappedClientChannel)
				timer := time.NewTimer(1 * time.Second)
				<-timer.C
				once.Do(allClose)
			}()

			defer once.Do(allClose)
		}
	}()

	for openedChannel := range clientChans {
		if stopped {
			break
		}

		clientChannel, clientReqs2, err := openedChannel.Accept()
		if err != nil {
			p.env.Red.Println("Couldn't accept channel on client:", err)
			return
		}

		if len(meta.SSHServerClient.Errors) > 0 {
			for _, v := range meta.SSHServerClient.Errors {
				clientChannel.Write([]byte("[bastion] " + v.Error()))
				clientChannel.Write([]byte{'\r', '\n'})
			}

			clientChannel.Close()
			return
		}

		proxyChannel, proxyReqs, err := proxyConn.OpenChannel(openedChannel.ChannelType(), openedChannel.ExtraData())
		if err != nil {
			p.env.Red.Println("Couldn't accept channel on proxy:", err)
			return
		}

		chanInfo := &config.ConnChan{
			ChannelType: openedChannel.ChannelType(),
			ChannelData: openedChannel.ExtraData(),
			Reqs:        make([]*config.ConnReq, 0),
			ClientConn:  clientConn,
			ProxyConn:   proxyConn,
			ProxyChan:   &proxyChannel,
			ClientChan:  &clientChannel,
		}
		meta.SSHChans = append(meta.SSHChans, chanInfo)

		closeParentChans := func() {
			proxyChannel.Close()
			clientChannel.Close()
		}

		go func() {
			for {
				var req *ssh.Request
				var dst ssh.Channel
				var reqFrom string
				var dstTo string

				select {
				case req = <-clientReqs2:
					dst = proxyChannel
					reqFrom = "client"
					dstTo = "proxy"
				case req = <-proxyReqs:
					dst = clientChannel
					reqFrom = "proxy"
					dstTo = "client"
				}

				if req == nil || dst == nil {
					break
				}

				b, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
				if err != nil {
					p.env.Red.Println("Error sending request through channel:", err)
				}

				if req.WantReply {
					req.Reply(b, nil)
				}

				reqInfo := &config.ConnReq{
					ReqType:  req.Type,
					ReqData:  req.Payload,
					ReqReply: req.WantReply,
				}

				meta.Mutex.Lock()
				chanInfo.Reqs = append(chanInfo.Reqs, reqInfo)
				meta.Mutex.Unlock()

				switch req.Type {
				case "shell":
					meta.Mutex.Lock()
					meta.SSHShellSessions = append(meta.SSHShellSessions, chanInfo)
					meta.Mutex.Unlock()

					if p.env.Vconfig.GetBool("multihost.enabled") {
						wholeCommand := ""

						for _, r := range chanInfo.Reqs {
							if r.ReqType == "shell" || r.ReqType == "exec" {
								command := ""
								if string(r.ReqData) == "" {
									command = "Main Shell"
								} else {
									command = string(r.ReqData)
								}

								if wholeCommand != "" {
									wholeCommand += ", " + command
								} else {
									wholeCommand += command
								}
								break
							}
						}

						livesession := &config.LiveSession{
							Name:            meta.SSHServerClient.Client.RemoteAddr().String(),
							Time:            time.Now(),
							Host:            meta.SSHServerClient.ProxyTo,
							Hostname:        meta.SSHServerClient.ProxyToHostname,
							Command:         wholeCommand,
							AuthCode:        RandStringBytesMaskImprSrc(20),
							WS:              p.RemoteAddr().String(),
							Bastion:         config.GetOutboundIP(p.env).String() + p.env.HTTPPort,
							BastionHostname: config.GetHostname(p.env),
						}

						if meta.SSHServerClient.User != nil {
							livesession.UserID = meta.SSHServerClient.User.ID
						}

						p.env.DB.Save(livesession)
						chanInfo.DBID = livesession.ID
					}
				case "exit-status":
					stopped = true
				}

				if stopped {
					break
				}
			}

			timer := time.NewTimer(1 * time.Second)
			<-timer.C
			closeParentChans()
		}()

		var wrappedClientChannel io.ReadCloser = clientChannel
		var wrappedProxyChannel = config.NewAsciicastReadCloser(proxyChannel, clientConn, 80, 40, chanInfo, p.env)

		closeChans := func() {
			wrappedClientChannel.Close()
			wrappedProxyChannel.Close()

			closeParentChans()
		}

		allClose := func() {
			closeChans()
		}

		var once sync.Once
		go func() {
			io.Copy(clientChannel, wrappedProxyChannel)
			timer := time.NewTimer(1 * time.Second)
			<-timer.C
			once.Do(allClose)
		}()
		go func() {
			io.Copy(proxyChannel, wrappedClientChannel)
			timer := time.NewTimer(1 * time.Second)
			<-timer.C
			once.Do(allClose)
		}()

		defer once.Do(allClose)
	}

	cleanup := func() {
		clientConn.Close()
		proxyConn.Close()
	}

	p.env.Magenta.Println("Closed proxy connection.")
	cleanup()
}

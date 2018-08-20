package ssh

import (
	"net"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"strings"
	"sync"
	"github.com/notion/trove_ssh_bastion/config"
)

type SshConn struct {
	net.Conn
	config     *ssh.ServerConfig
	callbackFn func(c ssh.ConnMetadata) (*ssh.Client, error)
	wrapFn     func(c ssh.ConnMetadata, r io.ReadCloser) (io.ReadCloser, error)
	closeFn    func(c ssh.ConnMetadata) error
	env        *config.Env
}

func (p *SshConn) serve() error {
	serverConn, chans, reqs, err := ssh.NewServerConn(p, p.config)
	if err != nil {
		log.Println("failed to handshake")
		return (err)
	}

	for chann := range chans {
		if chann.ChannelType() == "session" {
			connection, requests, err := chann.Accept()
			if err != nil {
				log.Println()
			}

			for req := range requests {
				if req.Type == "subsystem" {
					subsys := string(req.Payload[4:])

					if strings.HasPrefix(subsys, "proxy:") {
						log.Println("PROXYING")
						req.Reply(true, nil)

						host := strings.Replace(subsys, "proxy:", "", 1)

						conn, err := net.Dial("tcp", host)
						if err != nil {
							log.Println(err)
						}

						closeConn := func() {
							connection.Close()
							log.Printf("Proxy Session closed")
						}

						wrapFn(p.env)(serverConn, )

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
				}
			}
		}
	}

	defer serverConn.Close()

	clientConn, err := p.callbackFn(serverConn)
	if err != nil {
		log.Printf("%s", err.Error())
		return (err)
	}

	defer clientConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {

		channel2, requests2, err2 := clientConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
		if err2 != nil {
			log.Printf("Could not accept client channel: %s", err.Error())
			return err
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept server channel: %s", err.Error())
			return err
		}

		// connect requests
		go func() {
			log.Printf("Waiting for request")

		r:
			for {
				var req *ssh.Request
				var dst ssh.Channel

				select {
				case req = <-requests:
					dst = channel2
				case req = <-requests2:
					dst = channel
				}

				log.Printf("Request: %s %s %s %s\n", dst, req.Type, req.WantReply, req.Payload)

				b, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
				if err != nil {
					log.Printf("%s", err)
				}

				if req.WantReply {
					req.Reply(b, nil)
				}

				switch req.Type {
				case "exit-status":
					break r
				case "exec":
					// not supported (yet)
				default:
					log.Println(req.Type)
				}
			}

			channel.Close()
			channel2.Close()
		}()

		// connect channels
		log.Printf("Connecting channels.")

		var wrappedChannel io.ReadCloser = channel
		var wrappedChannel2 io.ReadCloser = channel2

		if p.wrapFn != nil {
			// wrappedChannel, err = p.wrapFn(channel)
			wrappedChannel2, err = p.wrapFn(serverConn, channel2)
		}

		go io.Copy(channel2, wrappedChannel)
		go io.Copy(channel, wrappedChannel2)

		defer wrappedChannel.Close()
		defer wrappedChannel2.Close()
	}

	if p.closeFn != nil {
		p.closeFn(serverConn)
	}

	return nil
}
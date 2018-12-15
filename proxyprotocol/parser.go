package proxyprotocol

import (
	"bufio"
	"log"
	"net"
	"time"

	"github.com/pires/go-proxyproto"
)

// ParseConn wraps a connection
func ParseConn(mainConn net.Conn, loggingEnabled bool) *Conn {
	reader := bufio.NewReader(mainConn)

	header, err := proxyproto.Read(reader)
	if err != nil && loggingEnabled {
		log.Println(err)
	}

	c := &Conn{
		cn:          mainConn,
		r:           reader,
		proxyheader: header,
	}

	return c
}

// Conn is the base wrapped proxy connection
type Conn struct {
	cn          net.Conn
	r           *bufio.Reader
	proxyheader *proxyproto.Header
}

// ProxyAddr returns the proxy remote network address.
func (c *Conn) ProxyAddr() net.Addr {
	return c.cn.RemoteAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	if c.proxyheader != nil {
		addr := &net.TCPAddr{
			IP:   c.proxyheader.SourceAddress,
			Port: int(c.proxyheader.SourcePort),
		}

		return addr
	}

	return c.ProxyAddr()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr { return c.cn.LocalAddr() }

// Read reads data from the connection.
func (c *Conn) Read(b []byte) (int, error) { return c.r.Read(b) }

// Close closes the connection.
func (c *Conn) Close() error { return c.cn.Close() }

// SetDeadline implements the Conn SetDeadline method.
func (c *Conn) SetDeadline(t time.Time) error { return c.cn.SetDeadline(t) }

// SetReadDeadline implements the Conn SetReadDeadline method.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.cn.SetReadDeadline(t) }

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.cn.SetWriteDeadline(t) }

// Write implements the Conn Write method.
func (c *Conn) Write(b []byte) (int, error) { return c.cn.Write(b) }

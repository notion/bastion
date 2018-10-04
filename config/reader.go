package config

import (
	"bytes"
	"cloud.google.com/go/storage"
	"compress/gzip"
	"context"
	"github.com/gorilla/websocket"
	"github.com/notion/trove_ssh_bastion/asciicast"
	"golang.org/x/crypto/ssh"
	"io"
	"strconv"
	"time"
)

func NewAsciicastReadCloser(r io.ReadCloser, conn ssh.ConnMetadata, width int, height int, chanInfo *ConnChan, env *Env) io.ReadCloser {
	closer := &AsciicastReadCloser{
		ReadCloser: r,
		SshConn:    conn,
		Time:       time.Now(),
		Cast: &asciicast.Cast{
			Header: &asciicast.Header{
				Version:   2,
				Width:     width,
				Height:    height,
				Timestamp: time.Now().Unix(),
			},
		},
		Env: env,
	}

	if env.LogsBucket != nil {
		bkt := env.LogsBucket

		ctx := context.Background()

		objHandler := bkt.Object(closer.Time.Format("2006-01-02 15:04:05") + " " + conn.RemoteAddr().String())
		w := objHandler.NewWriter(ctx)

		closer.BkWriter = w
		closer.BkContext = ctx

		closer.GZWriter = gzip.NewWriter(w)

		marshalledHeader, err := closer.Cast.Header.Marshal()
		if err != nil {
			env.Red.Println("Error marshalling header", err)
		}

		marshalledHeader = append(marshalledHeader, []byte("\n")...)

		_, err = closer.GZWriter.Write(marshalledHeader)
		if err != nil {
			env.Red.Println("Error writing header to bucket object", err)
		}
	}

	if val, ok := env.SshProxyClients.Load(conn.RemoteAddr().String()); ok {
		client := val.(*SshProxyClient)
		chanInfo.Closer = closer
		client.Mutex.Lock()
		closer.SidKey = strconv.Itoa(len(client.SshShellSessions))
		client.Mutex.Unlock()
		closer.User = client.SshServerClient.User
		closer.Host = client.SshServerClient.ProxyTo
	}

	return closer
}

type AsciicastReadCloser struct {
	io.ReadCloser

	SshConn   ssh.ConnMetadata
	Cast      *asciicast.Cast
	Time      time.Time
	Buffer    bytes.Buffer
	Env       *Env
	BkWriter  *storage.Writer
	BkContext context.Context
	GZWriter  *gzip.Writer
	User      *User
	Host      string
	SidKey    string
}

func (lr *AsciicastReadCloser) Read(p []byte) (n int, err error) {
	n, err = lr.ReadCloser.Read(p)

	now := time.Now()
	duration := now.Sub(lr.Time).Seconds()

	readBytes := p[0:n]

	if len(string(readBytes)) == 0 {
		return n, err
	}

	newFrame := &asciicast.Frame{
		Time:   duration,
		Event:  "o",
		Data:   string(readBytes),
		Author: lr.User.Email,
	}

	marshalledFrame, err := newFrame.Marshal()
	if err != nil {
		lr.Env.Red.Println("Error marshalling frame", err)
	}

	marshalledFrame = append(marshalledFrame, []byte("\n")...)

	_, err = lr.GZWriter.Write(marshalledFrame)
	if err != nil {
		lr.Env.Red.Println("Error writing frame to bucket object", err)
	}

	pathKey := lr.SshConn.RemoteAddr().String()
	sidKey := lr.SidKey

	if proxyClientInterface, ok := lr.Env.SshProxyClients.Load(pathKey); ok {
		proxyClient := proxyClientInterface.(*SshProxyClient)
		if clients, ok := lr.Env.WebsocketClients.Load(pathKey + sidKey); ok {
			wsClientMap := clients.(map[string]*WsClient)
			for _, v := range wsClientMap {
				proxyClient.Mutex.Lock()
				wsClient := v.Client
				wsWriter, err := wsClient.NextWriter(websocket.TextMessage)
				if err != nil {
					lr.Env.Red.Println("wsWriter error:", err)
				} else {
					wsWriter.Write(readBytes)
					wsWriter.Close()
				}
				proxyClient.Mutex.Unlock()
			}
		}
	}

	if len(lr.Cast.Frames) > 20 {
		lr.Cast.Frames = append(lr.Cast.Frames[1:], newFrame)
	} else {
		lr.Cast.Frames = append(lr.Cast.Frames, newFrame)
	}

	return n, err
}

func (lr *AsciicastReadCloser) Close() error {
	data, err := lr.Cast.Marshal()
	if err != nil {
		lr.Env.Red.Println("Error logging session", err)
	}

	session := &Session{
		Name: lr.BkWriter.Name,
		Time: lr.Time,
		Cast: data,
		Host: lr.Host,
	}

	if lr.User != nil {
		session.UserID = lr.User.ID
	}

	lr.Env.DB.Save(session)

	err = lr.GZWriter.Close()
	err = lr.BkWriter.Close()
	if err != nil {
		lr.Env.Red.Println("Error closing bucket writer", err)
	}

	return lr.ReadCloser.Close()
}

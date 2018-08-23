package asciicast

import (
	"io"
	"time"
	"bytes"
	"log"
	"github.com/notion/trove_ssh_bastion/config"
	"golang.org/x/crypto/ssh"
	"github.com/gorilla/websocket"
	"github.com/fatih/color"
	"context"
	"cloud.google.com/go/storage"
)

func NewAsciicastReadCloser(r io.ReadCloser, conn ssh.ConnMetadata, width int, height int, env *config.Env) io.ReadCloser {
	closer :=  &AsciicastReadCloser{
		ReadCloser: r,
		SshConn: conn,
		Time: time.Now(),
		Cast: &Cast{
			Header: &Header{
				Version: 2,
				Width: width,
				Height: height,
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

		marshalledHeader, err := closer.Cast.Header.Marshal()
		if err != nil {
			log.Println("Error marshalling header", err)
		}

		marshalledHeader = append(marshalledHeader, []byte("\n")...)

		_, err = w.Write(marshalledHeader)
		if err != nil {
			log.Println("Error writing header to bucket object", err)
		}
	}

	return closer
}

type AsciicastReadCloser struct {
	io.ReadCloser

	SshConn ssh.ConnMetadata
	Cast   *Cast
	Time   time.Time
	Buffer bytes.Buffer
	Env    *config.Env
	BkWriter *storage.Writer
	BkContext context.Context
}

func (lr *AsciicastReadCloser) Read(p []byte) (n int, err error) {
	n, err = lr.ReadCloser.Read(p)

	now := time.Now()
	duration := now.Sub(lr.Time).Seconds()

	newFrame := &Frame{
		Time: duration,
		Event: "o",
		Data: bytes.NewBuffer(p[0:n]).String(),
	}

	marshalledFrame, err := newFrame.Marshal()
	if err != nil {
		log.Println("Error marshalling frame", err)
	}

	marshalledFrame = append(marshalledFrame, []byte("\n")...)

	_, err = lr.BkWriter.Write(marshalledFrame)
	if err != nil {
		log.Println("Error writing frame to bucket object", err)
	}

	pathKey := lr.SshConn.RemoteAddr().String()

	if _, ok := lr.Env.SshProxyClients[pathKey]; ok {
		if _, ok := lr.Env.WebsocketClients[pathKey]; ok {
			for _, v := range lr.Env.WebsocketClients[pathKey] {
				wsClient := v.Client
				wsWriter, err := wsClient.NextWriter(websocket.TextMessage)
				if err != nil {
					color.Set(color.FgRed)
					log.Println("wsWriter error:", err)
					color.Unset()
				} else {
					wsWriter.Write(p[0:n])
					wsWriter.Close()
				}
			}
		}
	}

	lr.Cast.Frames = append(lr.Cast.Frames, newFrame)

	return n, err
}

func (lr *AsciicastReadCloser) Close() error {
	data, err := lr.Cast.Marshal()
	if err != nil {
		log.Println("Error logging session", err)
	}

	session := &config.Session{
		Time: lr.Time,
		Cast: data,
	}

	lr.Env.DB.Save(session)

	err = lr.BkWriter.Close()
	if err != nil {
		log.Println("Error closing bucket writer", err)
	}

	return lr.ReadCloser.Close()
}

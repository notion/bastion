package config

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/notion/bastion/asciicast"
	"golang.org/x/crypto/ssh"
)

// NewAsciicastReadCloser initializes an AsciiCast ReaderCloser for SSH logging
func NewAsciicastReadCloser(r io.ReadCloser, conn ssh.ConnMetadata, width int, height int, chanInfo *ConnChan, env *Env) io.ReadCloser {
	closer := &AsciicastReadCloser{
		ReadCloser: r,
		SSHConn:    conn,
		Time:       time.Now(),
		Cast: &asciicast.Cast{
			Header: &asciicast.Header{
				Version:   2,
				Width:     width,
				Height:    height,
				Timestamp: time.Now().Unix(),
			},
		},
		Env:      env,
		Mutex:    &sync.Mutex{},
		ChanInfo: chanInfo,
	}

	if val, ok := env.SSHProxyClients.Load(conn.RemoteAddr().String()); ok {
		client := val.(*SSHProxyClient)
		chanInfo.Closer = closer
		client.Mutex.Lock()
		closer.SidKey = strconv.Itoa(len(client.SSHShellSessions))
		client.Mutex.Unlock()
		closer.User = client.SSHServerClient.User
		closer.Host = client.SSHServerClient.ProxyTo
		closer.Hostname = client.SSHServerClient.ProxyToHostname
		closer.Name = client.SSHServerClient.Client.RemoteAddr().String()
		closer.FileName = closer.Time.Format("2006-01-02 15:04:05") + " " + closer.Name
		closer.Users = closer.User.Email
	}

	var w io.WriteCloser
	if env.LogsBucket != nil {
		bkt := env.LogsBucket

		ctx := context.Background()

		objHandler := bkt.Object(closer.FileName)
		w = objHandler.NewWriter(ctx)

		closer.BkWriter = w
		closer.BkContext = ctx
	} else if env.Vconfig.GetBool("sessions.enabled") {
		_ = os.Mkdir(env.Vconfig.GetString("sessions.directory"), os.ModePerm)

		file, err := os.Create(path.Join(env.Vconfig.GetString("sessions.directory"), closer.FileName))
		if err != nil {
			env.Red.Println("Error creating file to disk", err)
		}
		closer.BkWriter = file
		w = file
	}

	if w != nil {
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

	return closer
}

// AsciicastReadCloser is the main Asciicast ReadCloser
type AsciicastReadCloser struct {
	io.ReadCloser

	Name        string
	FileName    string
	SSHConn     ssh.ConnMetadata
	Cast        *asciicast.Cast
	Time        time.Time
	Buffer      bytes.Buffer
	Env         *Env
	BkWriter    io.WriteCloser
	BkContext   context.Context
	GZWriter    *gzip.Writer
	User        *User
	Host        string
	Hostname    string
	SidKey      string
	CurrentUser string
	Mutex       *sync.Mutex
	Users       string
	ChanInfo    *ConnChan
}

func (lr *AsciicastReadCloser) Read(p []byte) (n int, err error) {
	n, err = lr.ReadCloser.Read(p)

	now := time.Now()
	duration := now.Sub(lr.Time).Seconds()

	readBytes := p[0:n]

	if len(string(readBytes)) == 0 {
		return n, err
	}

	lr.Mutex.Lock()
	currentUser := lr.CurrentUser
	lr.Mutex.Unlock()

	if currentUser == "" {
		currentUser = lr.User.Email
	}

	newFrame := &asciicast.Frame{
		Time:   duration,
		Event:  "o",
		Data:   string(readBytes),
		Author: currentUser,
	}

	if !strings.Contains(lr.Users, currentUser) {
		lr.Users += ", " + currentUser
	}

	if currentUser != "" && strings.HasSuffix(string(readBytes), ":~# ") {
		lr.Mutex.Lock()
		lr.CurrentUser = ""
		lr.Mutex.Unlock()
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

	pathKey := lr.SSHConn.RemoteAddr().String()
	sidKey := lr.SidKey

	if proxyClientInterface, ok := lr.Env.SSHProxyClients.Load(pathKey); ok {
		proxyClient := proxyClientInterface.(*SSHProxyClient)
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

// Close closes the ReadCloser and uploads it to Google Cloud Storage
func (lr *AsciicastReadCloser) Close() error {
	data, err := lr.Cast.Marshal()
	if err != nil {
		lr.Env.Red.Println("Error logging session", err)
	}

	dbid := lr.ChanInfo.DBID
	if val, ok := lr.Env.SSHProxyClients.Load(lr.SSHConn.RemoteAddr().String()); ok {
		client := val.(*SSHProxyClient)

		sid, err := strconv.Atoi(lr.SidKey)
		if err == nil {
			dbid = client.SSHShellSessions[sid].DBID
		}

		client.Mutex.Lock()
		for _, v := range lr.ChanInfo.Reqs {
			if v.ReqType == "shell" || v.ReqType == "exec" {
				command := ""
				if string(v.ReqData) == "" {
					command = "Main Shell"
				} else {
					command = string(v.ReqData)
				}

				lr.Cast.Header.Command = command
				break
			}
		}
		client.Mutex.Unlock()
	}

	session := &Session{
		Name:     lr.FileName,
		Time:     lr.Time,
		Cast:     data,
		Host:     lr.Host,
		Hostname: lr.Hostname,
		Users:    lr.Users,
		Command:  lr.Cast.Header.Command,
	}

	if lr.User != nil {
		session.UserID = lr.User.ID
	}

	lr.Env.DB.Save(session)

	if lr.Env.Vconfig.GetBool("multihost.enabled") {
		lr.Env.DB.Delete(&LiveSession{}, dbid)
	}

	err = lr.GZWriter.Close()
	err = lr.BkWriter.Close()
	if err != nil {
		lr.Env.Red.Println("Error closing bucket writer", err)
	}

	return lr.ReadCloser.Close()
}

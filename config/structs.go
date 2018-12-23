package config

import (
	"net"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Env is our main context. A pointer of this is passed almost everywhere
type Env struct {
	ForceGeneration  bool
	PKPassphrase     string
	SSHServerClients *sync.Map
	SSHProxyClients  *sync.Map
	WebsocketClients *sync.Map
	DB               *gorm.DB
	Config           *Config
	LogsBucket       *storage.BucketHandle
	Vconfig          *viper.Viper
	Red              *ColorLog
	Green            *ColorLog
	Yellow           *ColorLog
	Blue             *ColorLog
	Magenta          *ColorLog
	SSHPort          string
	SSHProxyPort     string
	HTTPPort         string
	MonPort          string
}

// WsClient is a struct that contains a websockets underlying data object
type WsClient struct {
	Client *websocket.Conn
}

// SSHServerClient is a struct containing the client (user's) SSH connection
type SSHServerClient struct {
	Client          *ssh.ServerConn
	RawProxyConn    net.Conn
	ProxyTo         string
	ProxyToHostname string
	Username        string
	Password        string
	PublicKey       ssh.PublicKey
	Agent           *agent.Agent
	User            *User
	Errors          []error
	Time            time.Time
}

// SSHProxyClient is a struct containing the proxy (server's) SSH connection
type SSHProxyClient struct {
	Client           net.Conn
	SSHConn          ssh.Conn
	SSHClient        *ssh.Client
	SSHClientChans   <-chan ssh.NewChannel
	SSHClientReqs    <-chan *ssh.Request
	SSHServerClient  *SSHServerClient
	SSHShellSessions []*ConnChan
	SSHChans         []*ConnChan
	Mutex            *sync.Mutex
}

// ConnReq handles logged data from an SSH Request
type ConnReq struct {
	ReqType  string
	ReqData  []byte
	ReqReply bool
}

// ConnChan handles logged data from an SSH Channel
type ConnChan struct {
	ChannelType string
	ChannelData []byte
	Reqs        []*ConnReq
	ClientConn  *ssh.ServerConn
	ProxyConn   ssh.Conn
	ProxyChan   *ssh.Channel
	ClientChan  *ssh.Channel
	Closer      *AsciicastReadCloser
	DBID        uint
}

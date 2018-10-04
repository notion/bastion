package config

import (
	"cloud.google.com/go/storage"
	"context"
	"github.com/fatih/color"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"google.golang.org/api/option"
	"net"
	"os"
	"sync"
	"time"
)

type Config struct {
	gorm.Model
	Expires          string `gorm:"default:'48h'"`
	PrivateKey       []byte
	UserPrivateKey   []byte
	ServerPrivateKey []byte
}

type User struct {
	gorm.Model
	Email       string `gorm:"type:varchar(255);"`
	AuthToken   string `gorm:"type:MEDIUMTEXT;"`
	CertExpires time.Time
	Cert        []byte
	PrivateKey  []byte
	Authorized  bool   `gorm:"default:false"`
	Admin       bool   `gorm:"default:false"`
	UnixUser    string `gorm:"type:varchar(255);"`
}

type Session struct {
	gorm.Model
	Name   string
	Time   time.Time
	Cast   string `gorm:"type:LONGTEXT;"`
	UserID uint
	User   *User
	Host   string
}

type Env struct {
	ForceGeneration  bool
	PKPassphrase     string
	SshServerClients *sync.Map
	SshProxyClients  *sync.Map
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
}

type WsClient struct {
	Client *websocket.Conn
}

type SshServerClient struct {
	Client       *ssh.ServerConn
	RawProxyConn net.Conn
	ProxyTo      string
	Username     string
	Password     string
	PublicKey    ssh.PublicKey
	Agent        *agent.Agent
	User         *User
}

type SshProxyClient struct {
	Client           net.Conn
	SshClient        *ssh.Client
	SshServerClient  *SshServerClient
	SshShellSessions []*ConnChan
	SshChans         []*ConnChan
	Closer           *AsciicastReadCloser
	Mutex            *sync.Mutex
}

type ConnReq struct {
	ReqType  string
	ReqData  []byte
	ReqReply bool
}

type ConnChan struct {
	ChannelType string
	ChannelData []byte
	Reqs        []*ConnReq
	ClientConn  *ssh.ServerConn
	ProxyConn   *ssh.Client
	ProxyChan   *ssh.Channel
	ClientChan  *ssh.Channel
	Closer      *AsciicastReadCloser
}

var configFile = "config.yml"

func Load(forceCerts bool) *Env {
	vconfig := viper.New()

	vconfig.SetConfigFile(configFile)
	vconfig.ReadInConfig()

	red := NewColorLog(color.New(color.FgRed))
	green := NewColorLog(color.New(color.FgGreen))
	yellow := NewColorLog(color.New(color.FgYellow))
	blue := NewColorLog(color.New(color.FgBlue))
	magenta := NewColorLog(color.New(color.FgMagenta))

	db, err := gorm.Open("sqlite3", "trove_ssh_bastion.db")
	if err != nil {
		red.Println("Error loading config:", err)
	}
	db.LogMode(os.Getenv("DEBUG") == "true")

	db.AutoMigrate(&Config{}, &User{}, &Session{})

	var config Config

	db.First(&config)

	if config.Expires == "" {
		config.Expires = "48h"
	}

	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx, option.WithCredentialsFile("credentials.json"))
	if err != nil {
		red.Println("Error initializing google cloud storage", err)
	}

	bucketName := os.Getenv("BUCKET_NAME")
	if bucketName == "" {
		bucketName = "***REMOVED***"
	}
	logsBucket := storageClient.Bucket(bucketName)

	return &Env{
		ForceGeneration:  forceCerts,
		PKPassphrase:     os.Getenv("PKPASSPHRASE"),
		SshServerClients: &sync.Map{},
		SshProxyClients:  &sync.Map{},
		WebsocketClients: &sync.Map{},
		Config:           &config,
		DB:               db,
		LogsBucket:       logsBucket,
		Vconfig:          vconfig,
		Red:              red,
		Green:            green,
		Yellow:           yellow,
		Blue:             blue,
		Magenta:          magenta,
	}
}

func Save(env *Env) {
	env.DB.Save(env.Config)
	env.Vconfig.WriteConfigAs(configFile)
}

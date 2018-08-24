package config

import (
	"cloud.google.com/go/storage"
	"context"
	"github.com/fatih/color"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"google.golang.org/api/option"
	"log"
	"net"
	"os"
	"time"
)

type Config struct {
	gorm.Model
	PrivateKey []byte
}

type User struct {
	gorm.Model
	Email string `gorm:"type:varchar(255);"`
	AuthToken string `gorm:"type:MEDIUMTEXT;"`
	PrivateKey []byte
}

type Session struct {
	gorm.Model
	Name string
	Time time.Time
	Cast string `gorm:"type:LONGTEXT;"`
	UserID uint
	User *User
	Host string
}

type Env struct {
	SshServerClients map[string]*SshServerClient
	SshProxyClients map[string]*SshProxyClient
	WebsocketClients map[string]map[string]*WsClient
	DB *gorm.DB
	Config *Config
	LogsBucket *storage.BucketHandle
}

type WsClient struct {
	Client *websocket.Conn
}

type SshServerClient struct {
	Client *ssh.ServerConn
	RawProxyConn net.Conn
	ProxyTo string
	Username string
	Password string
	PublicKey ssh.PublicKey
	Agent *agent.Agent
	User *User
}

type SshProxyClient struct {
	Client net.Conn
	SshClient *ssh.Client
	SshServerClient *SshServerClient
	SshShellSession *ssh.Channel
	Closer *AsciicastReadCloser
}

func Load() *Env {
	db, err := gorm.Open("sqlite3", "trove_ssh_bastion.db")
	if err != nil {
		color.Set(color.FgRed)
		log.Println("Error loading config:", err)
		color.Unset()
	}
	db.LogMode(true)

	db.AutoMigrate(&Config{}, &User{}, &Session{})

	var config Config

	db.First(&config)

	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx, option.WithCredentialsFile(os.Getenv("HOME") + "/Downloads/***REMOVED***-89a4bde34ffb.json"))
	if err != nil {
		log.Println("Error initializing google cloud storage", err)
	}

	logsBucket := storageClient.Bucket("***REMOVED***")

	return &Env{
		SshServerClients: make(map[string]*SshServerClient, 0),
		SshProxyClients: make(map[string]*SshProxyClient, 0),
		WebsocketClients: make(map[string]map[string]*WsClient, 0),
		Config: &config,
		DB: db,
		LogsBucket: logsBucket,
	}
}

func Save(env *Env) {
	env.DB.Save(env.Config)
}
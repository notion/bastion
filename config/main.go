package config

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/fatih/color"
	"log"
	"golang.org/x/crypto/ssh"
	"net/mail"
	"net"
	"os"
	"time"
	"golang.org/x/crypto/ssh/agent"
	"github.com/gorilla/websocket"
	"context"
	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

type Config struct {
	gorm.Model
	PrivateKey []byte
}

type User struct {
	gorm.Model
	Email mail.Address `gorm:"type:varchar(255);"`
	AuthToken string `gorm:"type:MEDIUMTEXT;"`
	PrivateKey []byte
}

type Session struct {
	gorm.Model
	//User *User
	Time time.Time
	Cast string `gorm:"type:LONGTEXT;"`
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
}

type SshProxyClient struct {
	Client net.Conn
	SshClient *ssh.Client
	SshServerClient *SshServerClient
	SshShellSession *ssh.Channel
}

func Load() *Env {
	db, err := gorm.Open("sqlite3", "trove_ssh_bastion.db")
	if err != nil {
		color.Set(color.FgRed)
		log.Println("Error loading config:", err)
		color.Unset()
	}

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
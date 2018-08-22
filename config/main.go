package config

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/fatih/color"
	"log"
	"golang.org/x/crypto/ssh"
	"net/mail"
	"net"
	"time"
	"golang.org/x/crypto/ssh/agent"
	"github.com/gorilla/websocket"
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

	return &Env{
		SshServerClients: make(map[string]*SshServerClient, 0),
		SshProxyClients: make(map[string]*SshProxyClient, 0),
		WebsocketClients: make(map[string]map[string]*WsClient, 0),
		Config: &config,
		DB: db,
	}
}

func Save(env *Env) {
	env.DB.Save(env.Config)
}
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
	SshServerClients map[net.Addr]*SshServerClient
	SshProxyClients map[net.Addr]*SshProxyClient
	DB *gorm.DB
	Config *Config
}

type SshServerClient struct {
	Client net.Conn
	Username string
	Password string
	PublicKey ssh.PublicKey
}

type SshProxyClient struct {
	Client *ssh.Client
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
		SshServerClients: make(map[net.Addr]*SshServerClient, 0),
		SshProxyClients: make(map[net.Addr]*SshProxyClient, 0),
		Config: &config,
		DB: db,
	}
}

func Save(env *Env) {
	env.DB.Save(env.Config)
}
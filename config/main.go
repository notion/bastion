package config

import (
	"context"
	"fmt"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"  // Load MySQL for GORM
	_ "github.com/jinzhu/gorm/dialects/sqlite" // Load SQLite for GORM
	"github.com/spf13/viper"
	"google.golang.org/api/option"
)

const configFile = "config.yml"

// Load initializes the Env pointer with data from the database and elsewhere
func Load(forceCerts bool, webAddr string, sshAddr string, sshProxyAddr string, monAddr string) *Env {
	vconfig := viper.New()

	vconfig.SetConfigFile(configFile)
	vconfig.ReadInConfig()

	red := NewColorLog(color.New(color.FgRed))
	green := NewColorLog(color.New(color.FgGreen))
	yellow := NewColorLog(color.New(color.FgYellow))
	blue := NewColorLog(color.New(color.FgBlue))
	magenta := NewColorLog(color.New(color.FgMagenta))

	var db *gorm.DB
	var err error
	if vconfig.GetBool("dbinfo.sqlite") {
		db, err = gorm.Open("sqlite3", "bastion.db")
	} else {
		db, err = gorm.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local", vconfig.GetString("dbinfo.user"), vconfig.GetString("dbinfo.pass"), vconfig.GetString("dbinfo.host"), vconfig.GetString("dbinfo.port"), vconfig.GetString("dbinfo.name")))
	}

	if err != nil {
		red.Println("Error loading config:", err)
	}
	db.LogMode(vconfig.GetBool("debug"))

	releaseMode := gin.ReleaseMode
	if vconfig.GetBool("debug") {
		releaseMode = gin.DebugMode
	}
	gin.SetMode(releaseMode)

	db.AutoMigrate(&Config{}, &User{}, &Session{}, &LiveSession{}, &AuthRules{})

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

	var logsBucket *storage.BucketHandle
	if vconfig.GetBool("gce.bucket.enabled") {
		bucketName := vconfig.GetString("gce.bucket.name")
		logsBucket = storageClient.Bucket(bucketName)
	}

	env := &Env{
		ForceGeneration:  forceCerts,
		PKPassphrase:     vconfig.GetString("pkpassphrase"),
		SSHServerClients: &sync.Map{},
		SSHProxyClients:  &sync.Map{},
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
		HTTPPort:         webAddr,
		SSHPort:          sshAddr,
		SSHProxyPort:     sshProxyAddr,
		MonPort:          monAddr,
	}

	if vconfig.GetBool("multihost.enabled") {
		db.Delete(LiveSession{}, "bastion = ?", GetOutboundIP(env).String()+env.HTTPPort)
	}

	return env
}

// Save saves current Env data into the database and configs
func Save(env *Env) {
	env.DB.Save(env.Config)
	env.Vconfig.WriteConfigAs(configFile)
}

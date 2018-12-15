package config

import (
	"time"

	"github.com/jinzhu/gorm"
)

// Config is the main config structure and DB Model
type Config struct {
	gorm.Model
	Expires          string `gorm:"default:'48h'"`
	PrivateKey       []byte `gorm:"type:varbinary(4096);"`
	UserPrivateKey   []byte `gorm:"type:varbinary(4096);"`
	ServerPrivateKey []byte `gorm:"type:varbinary(4096);"`
	DefaultHosts     string `gorm:"type:MEDIUMTEXT;"`
}

// User is the model for users and their data
type User struct {
	gorm.Model
	CertExpires     time.Time
	Email           string      `gorm:"type:varchar(255);"`
	AuthToken       string      `gorm:"type:MEDIUMTEXT;"`
	Cert            []byte      `gorm:"type:varbinary(4096);"`
	PrivateKey      []byte      `gorm:"type:varbinary(4096);"`
	Authorized      bool        `gorm:"default:false"`
	AuthorizedHosts string      `gorm:"type:MEDIUMTEXT;"`
	Admin           bool        `gorm:"default:false"`
	UnixUser        string      `gorm:"type:varchar(255);"`
	OTPSecret       string      `gorm:"type:varchar(255);"`
	AuthRules       []AuthRules `gorm:"many2many:user_auth_rules;"`
}

// AuthRules is the model for different authorization rules (regex)
type AuthRules struct {
	gorm.Model
	Name            string `gorm:"type:varchar(255);"`
	AuthorizedHosts string `gorm:"type:MEDIUMTEXT;"`
	UnixUser        string `gorm:"type:varchar(255);"`
}

// Session is the model for a specific SSH sessions
type Session struct {
	gorm.Model
	Name     string `gorm:"type:MEDIUMTEXT;"`
	Time     time.Time
	Cast     string `gorm:"type:LONGTEXT;"`
	UserID   uint
	User     *User
	Host     string `gorm:"type:MEDIUMTEXT;"`
	Hostname string `gorm:"type:MEDIUMTEXT;"`
	Users    string `gorm:"type:LONGTEXT;"`
	Command  string `gorm:"type:MEDIUMTEXT;"`
}

// LiveSession is the model for a specific live SSH session
type LiveSession struct {
	gorm.Model
	Name     string `gorm:"type:MEDIUMTEXT;"`
	WS       string `gorm:"type:MEDIUMTEXT;"`
	Time     time.Time
	UserID   uint
	User     *User
	Host     string `gorm:"type:MEDIUMTEXT;"`
	Hostname string `gorm:"type:MEDIUMTEXT;"`
	Command  string `gorm:"type:MEDIUMTEXT;"`
	Bastion  string `gorm:"type:MEDIUMTEXT;"`
	AuthCode string `gorm:"type:MEDIUMTEXT;"`
}

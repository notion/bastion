package config

import (
	"log"
	"net"
	"os"
	"sync"
)

var (
	serverIP       net.IP
	serverHostname string
	ipMu           = &sync.Mutex{}
	hostMu         = &sync.Mutex{}
)

// GetOutboundIP get's the outbound internal ip
// https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func GetOutboundIP(env *Env) net.IP {
	ip := env.Vconfig.GetString("multihost.ip")
	if ip != "" {
		realIP := net.ParseIP(ip)
		if realIP != nil {
			return serverIP
		}
	}

	if serverIP == nil {
		ipMu.Lock()
		defer ipMu.Unlock()

		conn, err := net.Dial("udp", "8.8.8.8:80")
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		localAddr := conn.LocalAddr().(*net.UDPAddr)

		serverIP = localAddr.IP
	}

	return serverIP
}

// GetHostname returns the hostname of the machine the bastion is running on
func GetHostname(env *Env) string {
	hostname := env.Vconfig.GetString("multihost.hostname")
	if hostname != "" {
		return hostname
	}

	if serverHostname == "" {
		hostMu.Lock()
		defer hostMu.Unlock()

		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}

		serverHostname = hostname
	}

	return serverHostname
}

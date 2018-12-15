package config

import (
	"log"
	"net"
)

// GetOutboundIP get's the outbound internal ip
// https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go
func GetOutboundIP(env *Env) net.IP {
	ip := env.Vconfig.GetString("multihost.ip")
	if ip != "" {
		realIP := net.ParseIP(ip)
		if realIP != nil {
			return realIP
		}
	}

	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

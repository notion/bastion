package ssh

import (
	"github.com/notion/bastion/config"
)

// Serve handles initializing the SSH Server and Proxy
func Serve(addr string, proxyAddr string, env *config.Env) {
	initializeCerts(env, env.ForceGeneration)

	go startProxyServer(proxyAddr, env)
	startServer(addr, proxyAddr, env)
}

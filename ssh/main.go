package ssh

import "github.com/notion/trove_ssh_bastion/config"

func Serve(addr string, proxyAddr string, env *config.Env) {
	go startProxyServer(proxyAddr, env)
	startServer(addr, env)
}

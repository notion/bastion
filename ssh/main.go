package ssh

import "github.com/notion/trove_ssh_bastion/config"

func Serve(addr string, env *config.Env) {
	startProxyServer(addr, env)
}

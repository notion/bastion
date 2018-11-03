package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/notion/trove_ssh_bastion/config"
	"github.com/notion/trove_ssh_bastion/ssh"
	"github.com/notion/trove_ssh_bastion/web"
)

var (
	gce          = flag.Bool("gce", false, "Tells the bastion that it is running on GCE with Identity-Aware-Proxy/Instance Groups/TCP Load balancing/Autoscaling enabled. This disables native oAuth and verifies IAP headers. It also set's the PROXY protocol headers for a TCP loadbalancer and enables sharing of livesessions")
	webAddr      = flag.String("web.addr", ":8080", "The address to listen for http connections on")
	sshAddr      = flag.String("ssh.addr", ":5222", "The address to listen for ssh connections on")
	sshProxyAddr = flag.String("ssh.proxy.addr", "localhost:22222", "The address to listen for ssh proxy connections on")
	forceCerts   = flag.Bool("ssh.force-certs", false, "Force certificate generation")
)

func main() {
	flag.Parse()

	env := config.Load(*forceCerts, *gce)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		for range c {
			shutdown(env)
			os.Exit(0)
		}
	}()

	go ssh.Serve(*sshAddr, *sshProxyAddr, env)
	web.Serve(*webAddr, env)

	defer shutdown(env)
}

func shutdown(env *config.Env) {
	config.Save(env)
	env.DB.Close()
}

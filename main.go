package main

import (
	"flag"
	"os"
	"os/signal"

	"github.com/notion/bastion/config"
	"github.com/notion/bastion/monitoring"
	"github.com/notion/bastion/ssh"
	"github.com/notion/bastion/web"
)

var (
	monAddr      = flag.String("mon.addr", ":9501", "The address to listen for prom connections on")
	webAddr      = flag.String("web.addr", ":8080", "The address to listen for http connections on")
	sshAddr      = flag.String("ssh.addr", ":5222", "The address to listen for ssh connections on")
	sshProxyAddr = flag.String("ssh.proxy.addr", "localhost:22222", "The address to listen for ssh proxy connections on")
	forceCerts   = flag.Bool("ssh.force-certs", false, "Force certificate generation")
)

func main() {
	flag.Parse()

	env := config.Load(*forceCerts, *webAddr, *sshAddr, *sshProxyAddr, *monAddr)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	go func() {
		for range c {
			shutdown(env)
			os.Exit(0)
		}
	}()

	go ssh.Serve(*sshAddr, *sshProxyAddr, env)
	go monitoring.Serve(*monAddr, env)
	web.Serve(*webAddr, env)

	defer shutdown(env)
}

func shutdown(env *config.Env) {
	config.Save(env)
	env.DB.Close()
}

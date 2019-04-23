package config

import (
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

func printDebugInfo(env *Env) {
	go func() {
		for {
			env.Green.Println("=======Start=========")
			env.Green.Println("====Goroutines====")
			env.Green.Println(runtime.NumGoroutine())
			env.Green.Println("====Server Clients=======")
			env.SSHServerClients.Range(func(key, value interface{}) bool {
				log.Println(key, value)
				return true
			})
			env.Green.Println("====Proxy Clients=======")
			env.SSHProxyClients.Range(func(key, value interface{}) bool {
				log.Println(key, value)
				return true
			})
			env.Green.Println("====Websocket Clients=======")
			env.WebsocketClients.Range(func(key, value interface{}) bool {
				log.Println(key, value)
				return true
			})
			env.Green.Println("========End==========")
			env.Green.Println()

			if env.Vconfig.GetBool("debug.info.gostacktrace") {
				pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
			}

			time.Sleep(2 * time.Second)
		}
	}()
}

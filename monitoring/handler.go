package monitoring

import (
	"log"
	"net/http"

	"github.com/notion/bastion/config"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Serve starts the prometheus monitoring exporter
func Serve(monAddr string, env *config.Env) {
	prometheus.MustRegister(NewBastionExporter(env))
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(monAddr, nil))
}

package monitoring

import (
	"time"

	"github.com/notion/bastion/config"
	"github.com/prometheus/client_golang/prometheus"
)

// BastionCollector is the main bastion collector for Prometheus
type BastionCollector struct {
	env *config.Env
}

const (
	namespace = "bastion"
)

var (
	bastionSessionsTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sessions", "total"),
		"Number of total bastion sessions",
		[]string{"bastionhost", "bastionip"}, nil,
	)
	bastionSessions = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "sessions", "uptime"),
		"Bastion sessions and their uptime",
		[]string{"bastionhost", "bastionip", "user", "proxyhost", "proxyip", "uptime", "userip", "id"}, nil,
	)
)

// NewBastionExporter returns a new bastion exporter
func NewBastionExporter(env *config.Env) BastionCollector {
	return BastionCollector{
		env: env,
	}
}

// Describe is the prometheus collector's way to describe metrics
func (c BastionCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

// Collect is the prometheus collector's way to assign values to metrics
func (c BastionCollector) Collect(ch chan<- prometheus.Metric) {
	bastionSessionsTotals, hostnames := getBastionSessionsTotal(c)
	for host, val := range bastionSessionsTotals {
		ch <- prometheus.MustNewConstMetric(
			bastionSessionsTotal,
			prometheus.GaugeValue,
			float64(val),
			hostnames[host],
			host,
		)
	}

	sessions := getBastionSessions(c)
	for _, val := range sessions {
		ch <- prometheus.MustNewConstMetric(
			bastionSessions,
			prometheus.GaugeValue,
			float64(val["uptime"].(time.Time).Unix()),
			val["bastionhost"].(string),
			val["bastionip"].(string),
			val["user"].(string),
			val["proxyhost"].(string),
			val["proxyip"].(string),
			val["uptime"].(time.Time).Format("2006-01-02 15:04:05"),
			val["userip"].(string),
			val["id"].(string),
		)
	}
}

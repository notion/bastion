package monitoring

import (
	"os"
	"strconv"

	"github.com/jinzhu/gorm"
	"github.com/notion/bastion/config"
)

func getBastionSessionsTotal(c BastionCollector) map[string]float64 {
	data := map[string]float64{}
	count := 0
	if c.env.Vconfig.GetBool("multihost.enabled") {
		type res struct {
			Bastion string
			Count   int
		}

		var results []res
		c.env.DB.Table("live_sessions").Select([]string{"bastion", "count(bastion) as count"}).Where(map[string]interface{}{"deleted_at": nil}).Group("bastion").Having("count(bastion) > ?", 1).Scan(&results)

		for _, v := range results {
			data[v.Bastion] = float64(v.Count)
		}
	} else {
		c.env.SSHProxyClients.Range(func(key interface{}, value interface{}) bool {
			count++
			return true
		})

		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}

		data[hostname] = float64(count)
	}

	return data
}

func getBastionSessions(c BastionCollector) []map[string]interface{} {
	data := make([]map[string]interface{}, 0)
	if c.env.Vconfig.GetBool("multihost.enabled") {
		var results []*config.LiveSession
		c.env.DB.Preload("User", func(db *gorm.DB) *gorm.DB {
			return db.Select([]string{"id", "email"})
		}).Select([]string{"created_at", "bastion", "user_id", "host", "hostname", "name", "id"}).Find(&results)

		for _, v := range results {
			data = append(data, map[string]interface{}{
				"host":      v.Host,
				"user":      v.User.Email,
				"proxyhost": v.Host,
				"hostname":  v.Hostname,
				"uptime":    v.CreatedAt,
				"userip":    v.Name,
				"id":        strconv.Itoa(int(v.ID)),
			})
		}
	} else {
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}

		count := 1
		c.env.SSHProxyClients.Range(func(key interface{}, value interface{}) bool {
			client := value.(*config.SSHProxyClient)

			data = append(data, map[string]interface{}{
				"host":      hostname,
				"user":      client.SSHServerClient.User.Email,
				"proxyhost": client.SSHServerClient.ProxyToHostname,
				"hostname":  client.SSHServerClient.ProxyTo,
				"uptime":    client.SSHServerClient.Time,
				"userip":    client.SSHServerClient.Client.RemoteAddr().String(),
				"id":        strconv.Itoa(count),
			})

			count++

			return true
		})
	}

	return data
}

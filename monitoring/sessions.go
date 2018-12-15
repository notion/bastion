package monitoring

import (
	"strconv"

	"github.com/jinzhu/gorm"
	"github.com/notion/bastion/config"
)

func getBastionSessionsTotal(c BastionCollector) (map[string]float64, map[string]string) {
	data := map[string]float64{}
	hostnames := map[string]string{}
	count := 0
	if c.env.Vconfig.GetBool("multihost.enabled") {
		type res struct {
			Bastion string
			Count   int
		}

		var results []res
		c.env.DB.Table("live_sessions").Select([]string{"bastion", "count(bastion) as count"}).Where(map[string]interface{}{"deleted_at": nil}).Group("bastion").Having("count(bastion) > ?", 0).Scan(&results)

		type res2 struct {
			Bastion         string
			BastionHostname string
		}

		var results2 []res2
		c.env.DB.Table("live_sessions").Select([]string{"distinct(bastion)", "bastion_hostname"}).Scan(&results2)

		for _, v := range results2 {
			hostnames[v.Bastion] = v.BastionHostname
			for _, v2 := range results {
				if v.Bastion != v2.Bastion {
					continue
				} else {
					data[v.Bastion] = float64(v2.Count)
					break
				}
			}
			if _, ok := data[v.Bastion]; !ok {
				data[v.Bastion] = float64(0)
			}
		}
	} else {
		c.env.SSHProxyClients.Range(func(key interface{}, value interface{}) bool {
			count++
			return true
		})

		data[config.GetOutboundIP(c.env).String()] = float64(count)
		hostnames[config.GetOutboundIP(c.env).String()] = config.GetHostname(c.env)
	}

	return data, hostnames
}

func getBastionSessions(c BastionCollector) []map[string]interface{} {
	data := make([]map[string]interface{}, 0)
	if c.env.Vconfig.GetBool("multihost.enabled") {
		var results []*config.LiveSession
		c.env.DB.Preload("User", func(db *gorm.DB) *gorm.DB {
			return db.Select([]string{"id", "email"})
		}).Select([]string{"created_at", "bastion", "bastion_hostname", "user_id", "host", "hostname", "name", "id"}).Find(&results)

		for _, v := range results {
			data = append(data, map[string]interface{}{
				"bastionhost": v.BastionHostname,
				"bastionip":   v.Bastion,
				"user":        v.User.Email,
				"proxyhost":   v.Hostname,
				"proxyip":     v.Host,
				"uptime":      v.CreatedAt,
				"userip":      v.Name,
				"id":          strconv.Itoa(int(v.ID)),
			})
		}
	} else {
		count := 1
		c.env.SSHProxyClients.Range(func(key interface{}, value interface{}) bool {
			client := value.(*config.SSHProxyClient)

			data = append(data, map[string]interface{}{
				"bastionhost": config.GetHostname(c.env),
				"bastionip":   config.GetOutboundIP(c.env).String() + c.env.HTTPPort,
				"user":        client.SSHServerClient.User.Email,
				"proxyhost":   client.SSHServerClient.ProxyToHostname,
				"proxyip":     client.SSHServerClient.ProxyTo,
				"uptime":      client.SSHServerClient.Time,
				"userip":      client.SSHServerClient.Client.RemoteAddr().String(),
				"id":          strconv.Itoa(count),
			})

			count++

			return true
		})
	}

	return data
}

package config

import (
	"math"
	"time"
)

func Alert(c chan AlertInfo, env *Env) {
	go listenForLoginAlert(c, env)
}

func listenForLoginAlert(c chan AlertInfo, env *Env) {
	// key is username, value is last login time
	sshLoginData := make(map[string]time.Time)
	// key is string version of IP network address and val is bool
	seenNetworks := make(map[string]bool)
	sshLoginThresholdData := New()
	const maxDataPoints = 1000000
	var doAlert bool

	for alertInfo := range c {
		networkBeenSeen := seenNetworks[alertInfo.IP.String()]
		if !networkBeenSeen {
			alertInfo.NewNetwork = true
			doAlert = true
		}
		if lastLoginTime, ok := sshLoginData[alertInfo.User]; ok {
			timeSince := float64(alertInfo.Timestamp.Sub(lastLoginTime))

			addToDeque(sshLoginThresholdData, timeSince, maxDataPoints)
			mean := float64(mean(sshLoginThresholdData))
			threshold := (3 * stdev(sshLoginThresholdData, mean)) + mean

			if timeSince > threshold {
				alertInfo.BeenAWhile = true
				doAlert = true
			}
		} else { // first login for this user
			alertInfo.FirstLogin = true
			doAlert = true
		}
		sshLoginData[alertInfo.User] = alertInfo.Timestamp
		if doAlert || !alertInfo.Success {
			go printAlert(alertInfo, env)
		}
	}
}

// deque is fixed size so it doesn't just keep growing infinitely with more logins.
func addToDeque(deque *Deque, timeSince float64, maxDataPoints int) {
	if deque.Size() >= maxDataPoints {
		deque.PopRight()
	}
	deque.PushLeft(timeSince)
}

func mean(deque *Deque) float64 {
	sum := 0.0
	for idx := 0; idx < deque.Size(); idx++ {
		val := deque.PopRight().(float64)
		sum += float64(val)
		deque.PushLeft(val)
	}
	return sum / float64(deque.Size())
}

func stdev(deque *Deque, mean float64) float64 {
	sum := 0.0
	for idx := 0; idx < deque.Size(); idx++ {
		val := deque.PopRight().(float64)
		sum += (mean - val) * (mean - val)
		deque.PushLeft(val)
	}
	return math.Sqrt(sum / float64(deque.Size()))
}

func printAlert(alertInfo AlertInfo, env *Env) {
	alertString := "ALERT!\n"
	if alertInfo.NewNetwork {
		alertString += "User just attempted connection from a new network.\n"
	}
	if !alertInfo.Success {
		alertString += "User unsuccessfully attempted SSH connection.\n"
	}
	if alertInfo.BeenAWhile {
		alertString += "This is the first time this user has attempted SSH connection in a long time.\n"
	}
	if alertInfo.FirstLogin {
		alertString += "This user has never attempted SSH connection before.\n"
	}
	alertString += "SSH login details for this alert:\n"
	alertString += "User: " + alertInfo.User + "\n"
	alertString += "Timestamp: " + alertInfo.Timestamp.Format("Mon Jan _2 15:04:05 2006") + "\n"
	alertString += "Network IP: " + alertInfo.IP.String() + "\n"
	alertString += "If this information is expected, you may ignore this alert."
	// atomic.
	env.Blue.Println(alertString)
}

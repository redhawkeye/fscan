package Plugins

import (
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"time"
)

// RabbitMQScan performs a scan on RabbitMQ service
func RabbitMQScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	Common.LogDebug("Trying default account guest/guest")

	// First, test the default account guest/guest
	user, pass := "guest", "guest"
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			Common.LogDebug(fmt.Sprintf("Retry %d for default account: guest/guest", retryCount+1))
		}

		done := make(chan struct {
			success bool
			err     error
		}, 1)

		go func() {
			success, err := RabbitMQConn(info, user, pass)
			select {
			case done <- struct {
				success bool
				err     error
			}{success, err}:
			default:
			}
		}()

		var err error
		select {
		case result := <-done:
			err = result.err
			if result.success && err == nil {
				successMsg := fmt.Sprintf("RabbitMQ service %s connected successfully Username: %v Password: %v", target, user, pass)
				Common.LogSuccess(successMsg)

				// Save result
				vulnResult := &Common.ScanResult{
					Time:   time.Now(),
					Type:   Common.VULN,
					Target: info.Host,
					Status: "vulnerable",
					Details: map[string]interface{}{
						"port":     info.Pports,
						"service":  "rabbitmq",
						"username": user,
						"password": pass,
						"type":     "weak-password",
					},
				}
				Common.SaveResult(vulnResult)
				return nil
			}
		case <-time.After(time.Duration(Common.Timeout) * time.Second):
			err = fmt.Errorf("Connection timeout")
		}

		if err != nil {
			errlog := fmt.Sprintf("RabbitMQ service %s attempt failed Username: %v Password: %v Error: %v",
				target, user, pass, err)
			Common.LogError(errlog)

			if retryErr := Common.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					continue
				}
				continue
			}
		}
		break
	}

	totalUsers := len(Common.Userdict["rabbitmq"])
	totalPass := len(Common.Passwords)
	total := totalUsers * totalPass
	tried := 0

	Common.LogDebug(fmt.Sprintf("Starting to try username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	// Iterate through other username and password combinations
	for _, user := range Common.Userdict["rabbitmq"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] Trying: %s:%s", tried, total, user, pass))

			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("Retry %d: %s:%s", retryCount+1, user, pass))
				}

				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := RabbitMQConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{success, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						successMsg := fmt.Sprintf("RabbitMQ service %s connected successfully Username: %v Password: %v",
							target, user, pass)
						Common.LogSuccess(successMsg)

						// Save result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "rabbitmq",
								"username": user,
								"password": pass,
								"type":     "weak-password",
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("Connection timeout")
				}

				if err != nil {
					errlog := fmt.Sprintf("RabbitMQ service %s attempt failed Username: %v Password: %v Error: %v",
						target, user, pass, err)
					Common.LogError(errlog)

					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							continue
						}
						continue
					}
				}
				break
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("Scan complete, tried %d combinations", tried+1))
	return tmperr
}

// RabbitMQConn attempts to connect to RabbitMQ
func RabbitMQConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// Construct AMQP URL
	amqpURL := fmt.Sprintf("amqp://%s:%s@%s:%s/", user, pass, host, port)

	// Configure connection
	config := amqp.Config{
		Dial: func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, timeout)
		},
	}

	// Attempt connection
	conn, err := amqp.DialConfig(amqpURL, config)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	// If connection is successful
	if conn != nil {
		return true, nil
	}

	return false, fmt.Errorf("Authentication failed")
}

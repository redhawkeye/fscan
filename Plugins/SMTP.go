package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SmtpScan performs a scan on SMTP service
func SmtpScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	Common.LogDebug("Trying anonymous access...")

	// First, test anonymous access
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		flag, err := SmtpConn(info, "", "")
		if flag && err == nil {
			msg := fmt.Sprintf("SMTP service %s allows anonymous access", target)
			Common.LogSuccess(msg)

			// Save anonymous access result
			result := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: info.Host,
				Status: "vulnerable",
				Details: map[string]interface{}{
					"port":      info.Ports,
					"service":   "smtp",
					"type":      "anonymous-access",
					"anonymous": true,
				},
			}
			Common.SaveResult(result)
			return err
		}
		if err != nil {
			errlog := fmt.Sprintf("smtp %s anonymous %v", target, err)
			Common.LogError(errlog)

			if retryErr := Common.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					return err
				}
				continue
			}
		}
		break
	}

	totalUsers := len(Common.Userdict["smtp"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting to try username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// Iterate through all username and password combinations
	for _, user := range Common.Userdict["smtp"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] Trying: %s:%s", tried, total, user, pass))

			// Retry loop
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("Retry %d: %s:%s", retryCount+1, user, pass))
				}

				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					flag, err := SmtpConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{flag, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						msg := fmt.Sprintf("SMTP service %s brute force successful Username: %v Password: %v", target, user, pass)
						Common.LogSuccess(msg)

						// Save successful brute force result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "smtp",
								"type":     "weak-password",
								"username": user,
								"password": pass,
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("Connection timeout")
				}

				if err != nil {
					errlog := fmt.Sprintf("SMTP service %s attempt failed Username: %v Password: %v Error: %v",
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

	Common.LogDebug(fmt.Sprintf("Scan complete, tried %d combinations", tried))
	return tmperr
}

// SmtpConn attempts SMTP connection
func SmtpConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second
	addr := fmt.Sprintf("%s:%s", host, port)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return false, err
	}
	defer client.Close()

	if user != "" {
		auth := smtp.PlainAuth("", user, pass, host)
		err = client.Auth(auth)
		if err != nil {
			return false, err
		}
	}

	err = client.Mail("test@test.com")
	if err != nil {
		return false, err
	}

	return true, nil
}

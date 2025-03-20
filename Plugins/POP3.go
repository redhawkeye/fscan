package Plugins

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"time"
)

func POP3Scan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	totalUsers := len(Common.Userdict["pop3"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting to try username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// Iterate through all username and password combinations
	for _, user := range Common.Userdict["pop3"] {
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
					isTLS   bool
				}, 1)

				go func(user, pass string) {
					success, isTLS, err := POP3Conn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
						isTLS   bool
					}{success, err, isTLS}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success && err == nil {
						successMsg := fmt.Sprintf("POP3 service %s Username: %v Password: %v", target, user, pass)
						if result.isTLS {
							successMsg += " (TLS)"
						}
						Common.LogSuccess(successMsg)

						// Save result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "pop3",
								"username": user,
								"password": pass,
								"type":     "weak-password",
								"tls":      result.isTLS,
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("Connection timeout")
				}

				if err != nil {
					errMsg := fmt.Sprintf("POP3 service %s Attempt failed Username: %v Password: %v Error: %v",
						target, user, pass, err)
					Common.LogError(errMsg)

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

func POP3Conn(info *Common.HostInfo, user string, pass string) (success bool, isTLS bool, err error) {
	timeout := time.Duration(Common.Timeout) * time.Second
	addr := fmt.Sprintf("%s:%s", info.Host, info.Ports)

	// First try a regular connection
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		if flag, err := tryPOP3Auth(conn, user, pass, timeout); err == nil {
			return flag, false, nil
		}
		conn.Close()
	}

	// If regular connection fails, try TLS connection
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, tlsConfig)
	if err != nil {
		return false, false, fmt.Errorf("Connection failed: %v", err)
	}
	defer conn.Close()

	success, err = tryPOP3Auth(conn, user, pass, timeout)
	return success, true, err
}

func tryPOP3Auth(conn net.Conn, user string, pass string, timeout time.Duration) (bool, error) {
	reader := bufio.NewReader(conn)
	conn.SetDeadline(time.Now().Add(timeout))

	// Read welcome message
	_, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("Failed to read welcome message: %v", err)
	}

	// Send username
	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(fmt.Sprintf("USER %s\r\n", user)))
	if err != nil {
		return false, fmt.Errorf("Failed to send username: %v", err)
	}

	// Read username response
	conn.SetDeadline(time.Now().Add(timeout))
	response, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("Failed to read username response: %v", err)
	}
	if !strings.Contains(response, "+OK") {
		return false, fmt.Errorf("Invalid username")
	}

	// Send password
	conn.SetDeadline(time.Now().Add(timeout))
	_, err = conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", pass)))
	if err != nil {
		return false, fmt.Errorf("Failed to send password: %v", err)
	}

	// Read password response
	conn.SetDeadline(time.Now().Add(timeout))
	response, err = reader.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("Failed to read password response: %v", err)
	}

	if strings.Contains(response, "+OK") {
		return true, nil
	}

	return false, fmt.Errorf("Authentication failed")
}

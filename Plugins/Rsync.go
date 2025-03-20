package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"strings"
	"time"
)

func RsyncScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	Common.LogDebug("Trying anonymous access...")

	// First, test anonymous access
	for retryCount := 0; retryCount < maxRetries; retryCount++ {
		if retryCount > 0 {
			Common.LogDebug(fmt.Sprintf("Retry %d for anonymous access", retryCount+1))
		}

		flag, err := RsyncConn(info, "", "")
		if flag && err == nil {
			Common.LogSuccess(fmt.Sprintf("Rsync service %s anonymous access successful", target))

			// Save anonymous access result
			result := &Common.ScanResult{
				Time:   time.Now(),
				Type:   Common.VULN,
				Target: info.Host,
				Status: "vulnerable",
				Details: map[string]interface{}{
					"port":    info.Ports,
					"service": "rsync",
					"type":    "anonymous-access",
				},
			}
			Common.SaveResult(result)
			return err
		}

		if err != nil {
			Common.LogError(fmt.Sprintf("Rsync service %s anonymous access failed: %v", target, err))
			if retryErr := Common.CheckErrs(err); retryErr != nil {
				if retryCount == maxRetries-1 {
					return err
					}
				continue
				}
			}
		break
		}

	totalUsers := len(Common.Userdict["rsync"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting to try username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	for _, user := range Common.Userdict["rsync"] {
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
					flag, err := RsyncConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						err     error
					}{flag && err == nil, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success {
						Common.LogSuccess(fmt.Sprintf("Rsync service %s brute force successful Username: %v Password: %v",
							target, user, pass))

						// Save brute force result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "rsync",
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
					Common.LogError(fmt.Sprintf("Rsync service %s attempt failed Username: %v Password: %v Error: %v",
						target, user, pass, err))
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

func RsyncConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// Establish connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	buffer := make([]byte, 1024)

	// 1. Read server initial greeting
	n, err := conn.Read(buffer)
	if err != nil {
		return false, err
	}

	greeting := string(buffer[:n])
	if !strings.HasPrefix(greeting, "@RSYNCD:") {
		return false, fmt.Errorf("Not an Rsync service")
	}

	// Get server version
	version := strings.TrimSpace(strings.TrimPrefix(greeting, "@RSYNCD:"))

	// 2. Respond with the same version
	_, err = conn.Write([]byte(fmt.Sprintf("@RSYNCD: %s\n", version)))
	if err != nil {
		return false, err
	}

	// 3. Select module - list available modules first
	_, err = conn.Write([]byte("#list\n"))
	if err != nil {
		return false, err
	}

	// 4. Read module list
	var moduleList strings.Builder
	for {
		n, err = conn.Read(buffer)
		if err != nil {
			break
		}
		chunk := string(buffer[:n])
		moduleList.WriteString(chunk)
		if strings.Contains(chunk, "@RSYNCD: EXIT") {
			break
		}
	}

	modules := strings.Split(moduleList.String(), "\n")
	for _, module := range modules {
		if strings.HasPrefix(module, "@RSYNCD") || module == "" {
			continue
		}

		// Get module name
		moduleName := strings.Fields(module)[0]

		// 5. Create new connection for each module to try authentication
		authConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), timeout)
		if err != nil {
			continue
		}
		defer authConn.Close()

		// Repeat initial handshake
		_, err = authConn.Read(buffer)
		if err != nil {
			authConn.Close()
			continue
		}

		_, err = authConn.Write([]byte(fmt.Sprintf("@RSYNCD: %s\n", version)))
		if err != nil {
			authConn.Close()
			continue
		}

		// 6. Select module
		_, err = authConn.Write([]byte(moduleName + "\n"))
		if err != nil {
			authConn.Close()
			continue
		}

		// 7. Wait for authentication challenge
		n, err = authConn.Read(buffer)
		if err != nil {
			authConn.Close()
			continue
		}

		authResponse := string(buffer[:n])
		if strings.Contains(authResponse, "@RSYNCD: OK") {
			// Module does not require authentication
			if user == "" && pass == "" {
				result := fmt.Sprintf("Rsync service %v:%v Module:%v No authentication required", host, port, moduleName)
				Common.LogSuccess(result)
				return true, nil
			}
		} else if strings.Contains(authResponse, "@RSYNCD: AUTHREQD") {
			if user != "" && pass != "" {
				// 8. Send authentication information
				authString := fmt.Sprintf("%s %s\n", user, pass)
				_, err = authConn.Write([]byte(authString))
				if err != nil {
					authConn.Close()
					continue
				}

				// 9. Read authentication result
				n, err = authConn.Read(buffer)
				if err != nil {
					authConn.Close()
					continue
				}

				if !strings.Contains(string(buffer[:n]), "@ERROR") {
					result := fmt.Sprintf("Rsync service %v:%v Module:%v Authentication successful Username: %v Password: %v",
						host, port, moduleName, user, pass)
					Common.LogSuccess(result)
					return true, nil
				}
			}
		}
		authConn.Close()
	}

	return false, fmt.Errorf("Authentication failed or no available modules")
}

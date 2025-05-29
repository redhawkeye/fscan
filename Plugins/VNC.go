package Plugins

import (
	"fmt"
	"github.com/mitchellh/go-vnc"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"time"
)

func VncScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	modename := "vnc"
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Start scanning %s", target))
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Start trying password combinations (Total passwords: %d)", totalPass))

	tried := 0

	// Traverse all passwords
	for _, pass := range Common.Passwords {
		tried++
		Common.LogDebug(fmt.Sprintf("[%d/%d] Trying password: %s", tried, totalPass, pass))

		// Retry loop
		for retryCount := 0; retryCount < maxRetries; retryCount++ {
			if retryCount > 0 {
				Common.LogDebug(fmt.Sprintf("Retrying password %d: %s", retryCount+1, pass))
			}

			done := make(chan struct {
				success bool
				err     error
			}, 1)

			go func(pass string) {
				success, err := VncConn(info, pass)
				select {
				case done <- struct {
					success bool
					err     error
				}{success, err}:
				default:
				}
			}(pass)

			var err error
			select {
			case result := <-done:
				err = result.err
				if result.success && err == nil {
					// Connection successful
					successLog := fmt.Sprintf("%s://%s Password: %v", modename, target, pass)
					Common.LogSuccess(successLog)

					// Save result
					vulnResult := &Common.ScanResult{
						Time:   time.Now(),
						Type:   Common.VULN,
						Target: info.Host,
						Status: "vulnerable",
						Details: map[string]interface{}{
							"port":     info.Ports,
							"service":  "vnc",
							"password": pass,
							"type":     "weak-password",
						},
					}
					Common.SaveResult(vulnResult)
					return nil
				}
			case <-time.After(time.Duration(Common.Timeout) * time.Second):
				err = fmt.Errorf("Connection timed out")
			}

			if err != nil {
				errlog := fmt.Sprintf("%s://%s Trying password: %v Error: %v",
					modename, target, pass, err)
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

	Common.LogDebug(fmt.Sprintf("Scan complete, tried %d passwords", tried))
	return tmperr
}

// VncConn attempts to establish a VNC connection
func VncConn(info *Common.HostInfo, pass string) (flag bool, err error) {
	flag = false
	Host, Port := info.Host, info.Ports

	// Establish TCP connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", Host, Port),
		time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	// Configure VNC client
	config := &vnc.ClientConfig{
		Auth: []vnc.ClientAuth{
			&vnc.PasswordAuth{
				Password: pass,
			},
		},
	}

	// Attempt VNC authentication
	client, err := vnc.Client(conn, config)
	if err == nil {
		defer client.Close()
		flag = true
	}

	return
}

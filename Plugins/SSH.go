package Plugins

import (
	"context"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

func SshScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	totalUsers := len(Common.Userdict["ssh"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting to try username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// Traverse all username and password combinations
	for _, user := range Common.Userdict["ssh"] {
		for _, pass := range Common.Passwords {
			tried++
			pass = strings.Replace(pass, "{user}", user, -1)
			Common.LogDebug(fmt.Sprintf("[%d/%d] Trying: %s:%s", tried, total, user, pass))

			// Retry loop
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				if retryCount > 0 {
					Common.LogDebug(fmt.Sprintf("Retry %d: %s:%s", retryCount+1, user, pass))
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(Common.Timeout)*time.Second)
				done := make(chan struct {
					success bool
					err     error
				}, 1)

				go func(user, pass string) {
					success, err := SshConn(info, user, pass)
					select {
					case <-ctx.Done():
					case done <- struct {
						success bool
						err     error
					}{success, err}:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success {
						successMsg := fmt.Sprintf("SSH authentication successful %s User:%v Pass:%v", target, user, pass)
						Common.LogSuccess(successMsg)

						// Save result
						details := map[string]interface{}{
							"port":     info.Ports,
							"service":  "ssh",
							"username": user,
							"password": pass,
							"type":     "weak-password",
						}

						// If key authentication is used, add key information
						if Common.SshKeyPath != "" {
							details["auth_type"] = "key"
							details["key_path"] = Common.SshKeyPath
							details["password"] = nil
						}

						// If a command is executed, add command information
						if Common.Command != "" {
							details["command"] = Common.Command
						}

						vulnResult := &Common.ScanResult{
							Time:    time.Now(),
							Type:    Common.VULN,
							Target:  info.Host,
							Status:  "vulnerable",
							Details: details,
						}
						Common.SaveResult(vulnResult)

						time.Sleep(100 * time.Millisecond)
						cancel()
						return nil
					}
				case <-ctx.Done():
					err = fmt.Errorf("Connection timeout")
				}

				cancel()

				if err != nil {
					errMsg := fmt.Sprintf("SSH authentication failed %s User:%v Pass:%v Err:%v",
						target, user, pass, err)
					Common.LogError(errMsg)

					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							return err
						}
						continue
					}
				}

				if Common.SshKeyPath != "" {
					Common.LogDebug("Detected SSH key path, stopping password attempts")
					return err
				}

				break
			}
		}
	}

	Common.LogDebug(fmt.Sprintf("Scan completed, tried %d combinations", tried))
	return tmperr
}

func SshConn(info *Common.HostInfo, user string, pass string) (flag bool, err error) {
	var auth []ssh.AuthMethod
	if Common.SshKeyPath != "" {
		pemBytes, err := ioutil.ReadFile(Common.SshKeyPath)
		if err != nil {
			return false, fmt.Errorf("Failed to read key: %v", err)
		}

		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return false, fmt.Errorf("Failed to parse key: %v", err)
		}
		auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		auth = []ssh.AuthMethod{ssh.Password(pass)}
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: time.Duration(Common.Timeout) * time.Millisecond,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", info.Host, info.Ports), config)
	if err != nil {
		return false, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return false, err
	}
	defer session.Close()

	// If a command needs to be executed
	if Common.Command != "" {
		_, err := session.CombinedOutput(Common.Command)
		if err != nil {
			return true, err
		}
	}

	return true, nil
}

package Plugins

import (
	"fmt"
	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

func Neo4jScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))

	// First test for unauthenticated access and default credentials
	initialChecks := []struct {
		user string
		pass string
	}{
		{"", ""},           // Unauthenticated
		{"neo4j", "neo4j"}, // Default credentials
	}

	Common.LogDebug("Trying default credentials...")
	for _, check := range initialChecks {
		Common.LogDebug(fmt.Sprintf("Trying: %s:%s", check.user, check.pass))
		flag, err := Neo4jConn(info, check.user, check.pass)
		if flag && err == nil {
			var msg string
			if check.user == "" {
				msg = fmt.Sprintf("Neo4j service %s can be accessed without authentication", target)
				Common.LogSuccess(msg)

				// Save result - Unauthenticated access
				result := &Common.ScanResult{
					Time:   time.Now(),
					Type:   Common.VULN,
					Target: info.Host,
					Status: "vulnerable",
					Details: map[string]interface{}{
						"port":    info.Ports,
						"service": "neo4j",
						"type":    "unauthorized-access",
					},
				}
				Common.SaveResult(result)
			} else {
				msg = fmt.Sprintf("Neo4j service %s default credentials are valid Username: %s Password: %s", target, check.user, check.pass)
				Common.LogSuccess(msg)

				// Save result - Default credentials
				result := &Common.ScanResult{
					Time:   time.Now(),
					Type:   Common.VULN,
					Target: info.Host,
					Status: "vulnerable",
					Details: map[string]interface{}{
						"port":     info.Ports,
						"service":  "neo4j",
						"type":     "default-credentials",
						"username": check.user,
						"password": check.pass,
					},
				}
				Common.SaveResult(result)
			}
			return err
		}
	}

	totalUsers := len(Common.Userdict["neo4j"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// Iterate through all username and password combinations
	for _, user := range Common.Userdict["neo4j"] {
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
					flag, err := Neo4jConn(info, user, pass)
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
						msg := fmt.Sprintf("Neo4j service %s brute force successful Username: %s Password: %s", target, user, pass)
						Common.LogSuccess(msg)

						// Save result - Successful brute force
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "neo4j",
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
					errlog := fmt.Sprintf("Neo4j service %s attempt failed Username: %s Password: %s Error: %v", target, user, pass, err)
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

	Common.LogDebug(fmt.Sprintf("Scan completed, tried %d combinations", tried))
	return tmperr
}

// Neo4jConn attempts Neo4j connection
func Neo4jConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// Construct Neo4j URL
	uri := fmt.Sprintf("bolt://%s:%s", host, port)

	// Configure driver options
	config := func(c *neo4j.Config) {
		c.SocketConnectTimeout = timeout
	}

	var driver neo4j.Driver
	var err error

	// Attempt to establish connection
	if user != "" || pass != "" {
		// Use authentication if credentials are provided
		driver, err = neo4j.NewDriver(uri, neo4j.BasicAuth(user, pass, ""), config)
	} else {
		// Use NoAuth if no credentials are provided
		driver, err = neo4j.NewDriver(uri, neo4j.NoAuth(), config)
	}

	if err != nil {
		return false, err
	}
	defer driver.Close()

	// Test connection
	err = driver.VerifyConnectivity()
	if err != nil {
		return false, err
	}

	return true, nil
}

package Plugins

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

// PostgresScan performs a scan on PostgreSQL service
func PostgresScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)
	maxRetries := Common.MaxRetries

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	totalUsers := len(Common.Userdict["postgresql"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting to try username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	for _, user := range Common.Userdict["postgresql"] {
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
					success, err := PostgresConn(info, user, pass)
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
						successMsg := fmt.Sprintf("PostgreSQL service %s connected successfully Username: %v Password: %v", target, user, pass)
						Common.LogSuccess(successMsg)

						// Save result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "postgresql",
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
					errMsg := fmt.Sprintf("PostgreSQL service %s attempt failed Username: %v Password: %v Error: %v", target, user, pass, err)
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

// PostgresConn attempts to connect to PostgreSQL
func PostgresConn(info *Common.HostInfo, user string, pass string) (bool, error) {
	timeout := time.Duration(Common.Timeout) * time.Second

	// Construct connection string
	connStr := fmt.Sprintf(
		"postgres://%v:%v@%v:%v/postgres?sslmode=disable",
		user, pass, info.Host, info.Ports,
	)

	// Establish database connection
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return false, err
	}
	defer db.Close()

	// Set connection parameters
	db.SetConnMaxLifetime(timeout)

	// Test connection
	if err = db.Ping(); err != nil {
		return false, err
	}

	return true, nil
}

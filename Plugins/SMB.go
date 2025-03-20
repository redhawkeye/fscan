package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/stacktitan/smb/smb"
	"strings"
	"time"
)

func SmbScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%s:%s", info.Host, info.Ports)

	// Iterate through all users
	for _, user := range Common.Userdict["smb"] {
		// Iterate through all passwords for the user
		for _, pass := range Common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)

			success, err := doWithTimeOut(info, user, pass)
			if success {
				// Build result message
				var successMsg string
				details := map[string]interface{}{
					"port":     info.Ports,
					"service":  "smb",
					"username": user,
					"password": pass,
					"type":     "weak-password",
				}

				if Common.Domain != "" {
					successMsg = fmt.Sprintf("SMB authentication successful %s %s\\%s:%s", target, Common.Domain, user, pass)
					details["domain"] = Common.Domain
				} else {
					successMsg = fmt.Sprintf("SMB authentication successful %s %s:%s", target, user, pass)
				}

				// Log success
				Common.LogSuccess(successMsg)

				// Save result
				result := &Common.ScanResult{
					Time:    time.Now(),
					Type:    Common.VULN,
					Target:  info.Host,
					Status:  "vulnerable",
					Details: details,
				}
				Common.SaveResult(result)
				return nil
			}

			if err != nil {
				errMsg := fmt.Sprintf("SMB authentication failed %s %s:%s %v", target, user, pass, err)
				Common.LogError(errMsg)

				// Wait for error log to print
				time.Sleep(100 * time.Millisecond)

				if strings.Contains(err.Error(), "account locked") {
					// Skip remaining passwords for the current user if account is locked
					break // Exit password loop, continue to next user
				}
			}
		}
	}

	return nil
}

func SmblConn(info *Common.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	options := smb.Options{
		Host:        info.Host,
		Port:        445,
		User:        user,
		Password:    pass,
		Domain:      Common.Domain,
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		defer session.Close()
		if session.IsAuthenticated {
			return true, nil
		}
		return false, fmt.Errorf("authentication failed")
	}

	// Clean up error message by removing newlines and extra spaces
	errMsg := strings.TrimSpace(strings.ReplaceAll(err.Error(), "\n", " "))
	if strings.Contains(errMsg, "NT Status Error") {
		switch {
		case strings.Contains(errMsg, "STATUS_LOGON_FAILURE"):
			err = fmt.Errorf("password incorrect")
		case strings.Contains(errMsg, "STATUS_ACCOUNT_LOCKED_OUT"):
			err = fmt.Errorf("account locked")
		case strings.Contains(errMsg, "STATUS_ACCESS_DENIED"):
			err = fmt.Errorf("access denied")
		case strings.Contains(errMsg, "STATUS_ACCOUNT_DISABLED"):
			err = fmt.Errorf("account disabled")
		case strings.Contains(errMsg, "STATUS_PASSWORD_EXPIRED"):
			err = fmt.Errorf("password expired")
		case strings.Contains(errMsg, "STATUS_USER_SESSION_DELETED"):
			return false, fmt.Errorf("session disconnected")
		default:
			err = fmt.Errorf("authentication failed")
		}
	}

	signal <- struct{}{}
	return false, err
}

func doWithTimeOut(info *Common.HostInfo, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{}, 1)
	result := make(chan struct {
		success bool
		err     error
	}, 1)

	go func() {
		success, err := SmblConn(info, user, pass, signal)
		select {
		case result <- struct {
			success bool
			err     error
		}{success, err}:
		default:
		}
	}()

	select {
	case r := <-result:
		return r.success, r.err
	case <-time.After(time.Duration(Common.Timeout) * time.Second):
		select {
		case r := <-result:
			return r.success, r.err
		default:
			return false, fmt.Errorf("connection timeout")
		}
	}
}

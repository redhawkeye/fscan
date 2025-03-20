package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// SmbScan2 performs authentication scan for SMB2 service, supporting both password and hash authentication
func SmbScan2(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return nil
	}

	// Use hash authentication mode
	if len(Common.HashBytes) > 0 {
		return smbHashScan(info)
	}

	// Use password authentication mode
	return smbPasswordScan(info)
}

func smbPasswordScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	hasprint := false

	// Iterate through each user
	for _, user := range Common.Userdict["smb"] {
		accountLocked := false // Add account lock flag

		// Iterate through all passwords for the user
		for _, pass := range Common.Passwords {
			if accountLocked { // Skip remaining passwords if account is locked
				break
			}

			pass = strings.ReplaceAll(pass, "{user}", user)

			// Retry loop
			for retryCount := 0; retryCount < Common.MaxRetries; retryCount++ {
				success, err, printed := Smb2Con(info, user, pass, []byte{}, hasprint)

				if printed {
					hasprint = true
				}

				if success {
					logSuccessfulAuth(info, user, pass, []byte{})
					return nil
				}

				if err != nil {
					logFailedAuth(info, user, pass, []byte{}, err)

					// Check if account is locked
					if strings.Contains(err.Error(), "account has been automatically locked") ||
						strings.Contains(err.Error(), "account has been locked") {
						accountLocked = true // Set lock flag
						break
					}

					// Other login failure cases
					if strings.Contains(err.Error(), "LOGIN_FAILED") ||
						strings.Contains(err.Error(), "Authentication failed") ||
						strings.Contains(err.Error(), "attempted logon is invalid") ||
						strings.Contains(err.Error(), "bad username or authentication") {
						break
					}

					if retryCount < Common.MaxRetries-1 {
						time.Sleep(time.Second * time.Duration(retryCount+2))
						continue
					}
				}
				break
			}
		}
	}

	return nil
}

func smbHashScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	hasprint := false

	// Iterate through each user
	for _, user := range Common.Userdict["smb"] {
		// Iterate through all hashes for the user
		for _, hash := range Common.HashBytes {
			// Retry loop
			for retryCount := 0; retryCount < Common.MaxRetries; retryCount++ {
				success, err, printed := Smb2Con(info, user, "", hash, hasprint)

				if printed {
					hasprint = true
				}

				if success {
					logSuccessfulAuth(info, user, "", hash)
					return nil
				}

				if err != nil {
					logFailedAuth(info, user, "", hash, err)

					// Check if account is locked
					if strings.Contains(err.Error(), "user account has been automatically locked") {
						// Account locked, skip remaining hashes for the user
						break
					}

					// Other login failure cases
					if strings.Contains(err.Error(), "LOGIN_FAILED") ||
						strings.Contains(err.Error(), "Authentication failed") ||
						strings.Contains(err.Error(), "attempted logon is invalid") ||
						strings.Contains(err.Error(), "bad username or authentication") {
						break
					}

					if retryCount < Common.MaxRetries-1 {
						time.Sleep(time.Second * time.Duration(retryCount+1))
						continue
					}
				}
				break
			}
		}
	}

	return nil
}

// logSuccessfulAuth logs successful authentication
func logSuccessfulAuth(info *Common.HostInfo, user, pass string, hash []byte) {
	credential := pass
	if len(hash) > 0 {
		credential = Common.HashValue
	}

	// Save successful authentication result
	result := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "success",
		Details: map[string]interface{}{
			"port":       info.Ports,
			"service":    "smb2",
			"username":   user,
			"domain":     Common.Domain,
			"type":       "weak-auth",
			"credential": credential,
			"auth_type":  map[bool]string{true: "hash", false: "password"}[len(hash) > 0],
		},
	}
	Common.SaveResult(result)

	// Console output
	var msg string
	if Common.Domain != "" {
		msg = fmt.Sprintf("SMB2 authentication successful %s:%s %s\\%s", info.Host, info.Ports, Common.Domain, user)
	} else {
		msg = fmt.Sprintf("SMB2 authentication successful %s:%s %s", info.Host, info.Ports, user)
	}

	if len(hash) > 0 {
		msg += fmt.Sprintf(" Hash:%s", Common.HashValue)
	} else {
		msg += fmt.Sprintf(" Pass:%s", pass)
	}
	Common.LogSuccess(msg)
}

// logFailedAuth logs failed authentication
func logFailedAuth(info *Common.HostInfo, user, pass string, hash []byte, err error) {
	var errlog string
	if len(hash) > 0 {
		errlog = fmt.Sprintf("SMB2 authentication failed %s:%s %s Hash:%s %v",
			info.Host, info.Ports, user, Common.HashValue, err)
	} else {
		errlog = fmt.Sprintf("SMB2 authentication failed %s:%s %s:%s %v",
			info.Host, info.Ports, user, pass, err)
	}
	errlog = strings.ReplaceAll(errlog, "\n", " ")
	Common.LogError(errlog)
}

// Smb2Con attempts SMB2 connection and authentication, checks share access permissions
func Smb2Con(info *Common.HostInfo, user string, pass string, hash []byte, hasprint bool) (flag bool, err error, flag2 bool) {
	// Establish TCP connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", info.Host),
		time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return false, fmt.Errorf("Connection failed: %v", err), false
	}
	defer conn.Close()

	// Configure NTLM authentication
	initiator := smb2.NTLMInitiator{
		User:   user,
		Domain: Common.Domain,
	}

	// Set authentication method (hash or password)
	if len(hash) > 0 {
		initiator.Hash = hash
	} else {
		initiator.Password = pass
	}

	// Create SMB2 session
	d := &smb2.Dialer{
		Initiator: &initiator,
	}
	session, err := d.Dial(conn)
	if err != nil {
		return false, fmt.Errorf("SMB2 session establishment failed: %v", err), false
	}
	defer session.Logoff()

	// Get share list
	shares, err := session.ListSharenames()
	if err != nil {
		return false, fmt.Errorf("Failed to get share list: %v", err), false
	}

	// Print share information (if not printed before)
	if !hasprint {
		logShareInfo(info, user, pass, hash, shares)
		flag2 = true
	}

	// Attempt to access C$ share to verify admin privileges
	fs, err := session.Mount("C$")
	if err != nil {
		return false, fmt.Errorf("Failed to mount C$: %v", err), flag2
	}
	defer fs.Umount()

	// Attempt to read system file to verify permissions
	path := `Windows\win.ini`
	f, err := fs.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return false, fmt.Errorf("Failed to access system file: %v", err), flag2
	}
	defer f.Close()

	return true, nil, flag2
}

// logShareInfo logs SMB share information
func logShareInfo(info *Common.HostInfo, user string, pass string, hash []byte, shares []string) {
	credential := pass
	if len(hash) > 0 {
		credential = Common.HashValue
	}

	// Save share information result
	result := &Common.ScanResult{
		Time:   time.Now(),
		Type:   Common.VULN,
		Target: info.Host,
		Status: "shares-found",
		Details: map[string]interface{}{
			"port":       info.Ports,
			"service":    "smb2",
			"username":   user,
			"domain":     Common.Domain,
			"shares":     shares,
			"credential": credential,
			"auth_type":  map[bool]string{true: "hash", false: "password"}[len(hash) > 0],
		},
	}
	Common.SaveResult(result)

	// Console output
	var msg string
	if Common.Domain != "" {
		msg = fmt.Sprintf("SMB2 share information %s:%s %s\\%s", info.Host, info.Ports, Common.Domain, user)
	} else {
		msg = fmt.Sprintf("SMB2 share information %s:%s %s", info.Host, info.Ports, user)
	}

	if len(hash) > 0 {
		msg += fmt.Sprintf(" Hash:%s", Common.HashValue)
	} else {
		msg += fmt.Sprintf(" Pass:%s", pass)
	}
	msg += fmt.Sprintf(" Shares:%v", shares)
	Common.LogInfo(msg)
}

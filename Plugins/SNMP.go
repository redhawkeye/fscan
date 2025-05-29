package Plugins

import (
	"fmt"
	"github.com/gosnmp/gosnmp"
	"github.com/shadow1ng/fscan/Common"
	"strconv"
	"strings"
	"time"
)

// SNMPScan executes SNMP service scan
func SNMPScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	portNum, _ := strconv.Atoi(info.Ports)
	defaultCommunities := []string{"public", "private", "cisco", "community"}
	timeout := time.Duration(Common.Timeout) * time.Second
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	Common.LogDebug(fmt.Sprintf("Trying default community list (total: %d)", len(defaultCommunities)))

	tried := 0
	total := len(defaultCommunities)

	for _, community := range defaultCommunities {
		tried++
		Common.LogDebug(fmt.Sprintf("[%d/%d] Trying community: %s", tried, total, community))

		for retryCount := 0; retryCount < maxRetries; retryCount++ {
			if retryCount > 0 {
				Common.LogDebug(fmt.Sprintf("Retry %d: community: %s", retryCount+1, community))
			}

			done := make(chan struct {
				success bool
				sysDesc string
				err     error
			}, 1)

			go func(community string) {
				success, sysDesc, err := SNMPConnect(info, community, portNum)
				select {
				case done <- struct {
					success bool
					sysDesc string
					err     error
				}{success, sysDesc, err}:
				default:
				}
			}(community)

			var err error
			select {
			case result := <-done:
				err = result.err
				if result.success && err == nil {
					successMsg := fmt.Sprintf("SNMP service %s community: %v connected successfully", target, community)
					if result.sysDesc != "" {
						successMsg += fmt.Sprintf(" System: %v", result.sysDesc)
					}
					Common.LogSuccess(successMsg)

					// Save result
					vulnResult := &Common.ScanResult{
						Time:   time.Now(),
						Type:   Common.VULN,
						Target: info.Host,
						Status: "vulnerable",
						Details: map[string]interface{}{
							"port":      info.Ports,
							"service":   "snmp",
							"community": community,
							"type":      "weak-community",
							"system":    result.sysDesc,
						},
					}
					Common.SaveResult(vulnResult)
					return nil
				}
			case <-time.After(timeout):
				err = fmt.Errorf("connection timeout")
			}

			if err != nil {
				errlog := fmt.Sprintf("SNMP service %s attempt failed community: %v error: %v",
					target, community, err)
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

	Common.LogDebug(fmt.Sprintf("Scan completed, tried %d communities", tried))
	return tmperr
}

// SNMPConnect attempts SNMP connection
func SNMPConnect(info *Common.HostInfo, community string, portNum int) (bool, string, error) {
	host := info.Host
	timeout := time.Duration(Common.Timeout) * time.Second

	snmp := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(portNum),
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1,
	}

	err := snmp.Connect()
	if err != nil {
		return false, "", err
	}
	defer snmp.Conn.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"}
	result, err := snmp.Get(oids)
	if err != nil {
		return false, "", err
	}

	if len(result.Variables) > 0 {
		var sysDesc string
		if result.Variables[0].Type != gosnmp.NoSuchObject {
			sysDesc = strings.TrimSpace(string(result.Variables[0].Value.([]byte)))
		}
		return true, sysDesc, nil
	}

	return false, "", fmt.Errorf("authentication failed")
}

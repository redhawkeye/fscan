package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"strings"
	"time"
)

// MongodbScan executes a MongoDB unauthorized scan
func MongodbScan(info *Common.HostInfo) error {
	if Common.DisableBrute {
		return nil
	}

	target := fmt.Sprintf("%s:%v", info.Host, info.Ports)
	isUnauth, err := MongodbUnauth(info)

	if err != nil {
		errlog := fmt.Sprintf("MongoDB %v %v", target, err)
		Common.LogError(errlog)
	} else if isUnauth {
		// Log console output
		Common.LogSuccess(fmt.Sprintf("MongoDB %v unauthorized access", target))

		// Save unauthorized access result
		result := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: info.Host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":     info.Ports,
				"service":  "mongodb",
				"type":     "unauthorized-access",
				"protocol": "mongodb",
			},
		}
		Common.SaveResult(result)
	}

	return err
}

// MongodbUnauth checks for MongoDB unauthorized access
func MongodbUnauth(info *Common.HostInfo) (bool, error) {
	msgPacket := createOpMsgPacket()
	queryPacket := createOpQueryPacket()

	realhost := fmt.Sprintf("%s:%v", info.Host, info.Ports)

	// Attempt OP_MSG query
	reply, err := checkMongoAuth(realhost, msgPacket)
	if err != nil {
		// If failed, attempt OP_QUERY query
		reply, err = checkMongoAuth(realhost, queryPacket)
		if err != nil {
			return false, err
		}
	}

	// Check response result
	if strings.Contains(reply, "totalLinesWritten") {
		return true, nil
	}

	return false, nil
}

// checkMongoAuth checks MongoDB authentication status
func checkMongoAuth(address string, packet []byte) (string, error) {
	// Establish TCP connection
	conn, err := Common.WrapperTcpWithTimeout("tcp", address, time.Duration(Common.Timeout)*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Set timeout
	if err := conn.SetReadDeadline(time.Now().Add(time.Duration(Common.Timeout) * time.Second)); err != nil {
		return "", err
	}

	// Send query packet
	if _, err := conn.Write(packet); err != nil {
		return "", err
	}

	// Read response
	reply := make([]byte, 1024)
	count, err := conn.Read(reply)
	if err != nil {
		return "", err
	}

	return string(reply[:count]), nil
}

// createOpMsgPacket creates an OP_MSG query packet
func createOpMsgPacket() []byte {
	return []byte{
		0x69, 0x00, 0x00, 0x00, // messageLength
		0x39, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xdd, 0x07, 0x00, 0x00, // opCode OP_MSG
		0x00, 0x00, 0x00, 0x00, // flagBits
		// sections db.adminCommand({getLog: "startupWarnings"})
		0x00, 0x54, 0x00, 0x00, 0x00, 0x02, 0x67, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x57, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x02, 0x24, 0x64, 0x62, 0x00, 0x06, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x00, 0x03, 0x6c, 0x73, 0x69, 0x64, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x05, 0x69, 0x64, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x6e, 0x81, 0xf8, 0x8e, 0x37, 0x7b, 0x4c, 0x97, 0x84, 0x4e, 0x90, 0x62, 0x5a, 0x54, 0x3c, 0x93, 0x00, 0x00,
	}
}

// createOpQueryPacket creates an OP_QUERY query packet
func createOpQueryPacket() []byte {
	return []byte{
		0x48, 0x00, 0x00, 0x00, // messageLength
		0x02, 0x00, 0x00, 0x00, // requestID
		0x00, 0x00, 0x00, 0x00, // responseTo
		0xd4, 0x07, 0x00, 0x00, // opCode OP_QUERY
		0x00, 0x00, 0x00, 0x00, // flags
		0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // fullCollectionName admin.$cmd
		0x00, 0x00, 0x00, 0x00, // numberToSkip
		0x01, 0x00, 0x00, 0x00, // numberToReturn
		// query db.adminCommand({getLog: "startupWarnings"})
		0x21, 0x00, 0x00, 0x00, 0x2, 0x67, 0x65, 0x74, 0x4c, 0x6f, 0x67, 0x00, 0x10, 0x00, 0x00, 0x00, 0x73, 0x74, 0x61, 0x72, 0x74, 0x75, 0x70, 0x57, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x73, 0x00, 0x00,
	}
}

package Plugins

import (
	"encoding/binary"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"time"
)

// ModbusScan executes a Modbus service scan
func ModbusScan(info *Common.HostInfo) error {
	host, port := info.Host, info.Ports
	timeout := time.Duration(Common.Timeout) * time.Second

	// Attempt to establish a connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", host, port), timeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Construct Modbus TCP request packet - Read Device ID
	request := buildModbusRequest()

	// Set read/write timeout
	conn.SetDeadline(time.Now().Add(timeout))

	// Send request
	_, err = conn.Write(request)
	if err != nil {
		return fmt.Errorf("Failed to send Modbus request: %v", err)
	}

	// Read response
	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil {
		return fmt.Errorf("Failed to read Modbus response: %v", err)
	}

	// Validate response
	if isValidModbusResponse(response[:n]) {
		// Get device information
		deviceInfo := parseModbusResponse(response[:n])

		// Save scan result
		result := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.VULN,
			Target: host,
			Status: "vulnerable",
			Details: map[string]interface{}{
				"port":      port,
				"service":   "modbus",
				"type":      "unauthorized-access",
				"device_id": deviceInfo,
			},
		}
		Common.SaveResult(result)

		// Console output
		Common.LogSuccess(fmt.Sprintf("Modbus service %v:%v has no authentication access", host, port))
		if deviceInfo != "" {
			Common.LogSuccess(fmt.Sprintf("Device information: %s", deviceInfo))
		}

		return nil
	}

	return fmt.Errorf("Not a Modbus service or access denied")
}

// buildModbusRequest constructs a Modbus TCP request packet
func buildModbusRequest() []byte {
	request := make([]byte, 12)

	// Modbus TCP header
	binary.BigEndian.PutUint16(request[0:], 0x0001) // Transaction Identifier
	binary.BigEndian.PutUint16(request[2:], 0x0000) // Protocol Identifier
	binary.BigEndian.PutUint16(request[4:], 0x0006) // Length
	request[6] = 0x01                               // Unit Identifier

	// Modbus request
	request[7] = 0x01                                // Function Code: Read Coils
	binary.BigEndian.PutUint16(request[8:], 0x0000)  // Starting Address
	binary.BigEndian.PutUint16(request[10:], 0x0001) // Quantity of Coils

	return request
}

// isValidModbusResponse validates if the Modbus response is valid
func isValidModbusResponse(response []byte) bool {
	if len(response) < 9 {
		return false
	}

	// Check Protocol Identifier
	protocolID := binary.BigEndian.Uint16(response[2:])
	if protocolID != 0 {
		return false
	}

	// Check Function Code
	funcCode := response[7]
	if funcCode == 0x81 { // Error response
		return false
	}

	return true
}

// parseModbusResponse parses the Modbus response to get device information
func parseModbusResponse(response []byte) string {
	if len(response) < 9 {
		return ""
	}

	unitID := response[6]
	return fmt.Sprintf("Unit ID: %d", unitID)
}

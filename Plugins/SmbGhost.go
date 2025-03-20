package Plugins

import (
	"bytes"
	"fmt"
	"time"

	"github.com/shadow1ng/fscan/Common"
)

const (
	pkt = "\x00" + // session
		"\x00\x00\xc0" + // legth

		"\xfeSMB@\x00" + // protocol

		//[MS-SMB2]: SMB2 NEGOTIATE Request
		//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5

		"\x00\x00" +
		"\x00\x00" +
		"\x00\x00" +
		"\x00\x00" +
		"\x1f\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +

		// [MS-SMB2]: SMB2 NEGOTIATE_CONTEXT
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/15332256-522e-4a53-8cd7-0bd17678a2f7

		"$\x00" +
		"\x08\x00" +
		"\x01\x00" +
		"\x00\x00" +
		"\x7f\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"x\x00" +
		"\x00\x00" +
		"\x02\x00" +
		"\x00\x00" +
		"\x02\x02" +
		"\x10\x02" +
		"\x22\x02" +
		"$\x02" +
		"\x00\x03" +
		"\x02\x03" +
		"\x10\x03" +
		"\x11\x03" +
		"\x00\x00\x00\x00" +

		// [MS-SMB2]: SMB2_PREAUTH_INTEGRITY_CAPABILITIES
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a07bd66-4734-4af8-abcf-5a44ff7ee0e5

		"\x01\x00" +
		"&\x00" +
		"\x00\x00\x00\x00" +
		"\x01\x00" +
		"\x20\x00" +
		"\x01\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00\x00\x00" +
		"\x00\x00" +

		// [MS-SMB2]: SMB2_COMPRESSION_CAPABILITIES
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/78e0c942-ab41-472b-b117-4a95ebe88271

		"\x03\x00" +
		"\x0e\x00" +
		"\x00\x00\x00\x00" +
		"\x01\x00" + //CompressionAlgorithmCount
		"\x00\x00" +
		"\x01\x00\x00\x00" +
		"\x01\x00" + //LZNT1
		"\x00\x00" +
		"\x00\x00\x00\x00"
)

// SmbGhost detects the SMB Ghost vulnerability (CVE-2020-0796)
func SmbGhost(info *Common.HostInfo) error {
	// Skip detection if brute force mode is enabled
	if Common.DisableBrute {
		return nil
	}

	// Perform the actual SMB Ghost vulnerability scan
	err := SmbGhostScan(info)
	return err
}

// SmbGhostScan performs the actual SMB Ghost vulnerability detection logic
func SmbGhostScan(info *Common.HostInfo) error {
	// Set scan parameters
	ip := info.Host
	port := 445 // Default port for SMB service
	timeout := time.Duration(Common.Timeout) * time.Second

	// Construct target address
	addr := fmt.Sprintf("%s:%v", ip, port)

	// Establish TCP connection
	conn, err := Common.WrapperTcpWithTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close() // Ensure the connection is closed

	// Send SMB protocol probe packet
	if _, err = conn.Write([]byte(pkt)); err != nil {
		return err
	}

	// Prepare to receive response
	buff := make([]byte, 1024)

	// Set read timeout
	if err = conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}

	// Read response data
	n, err := conn.Read(buff)
	if err != nil || n == 0 {
		return err
	}

	// Analyze response data to detect the vulnerability
	// Check conditions:
	// 1. Response contains "Public" string
	// 2. Response length is at least 76 bytes
	// 3. Signature bytes match (0x11,0x03) and (0x02,0x00)
	if bytes.Contains(buff[:n], []byte("Public")) &&
		len(buff[:n]) >= 76 &&
		bytes.Equal(buff[72:74], []byte{0x11, 0x03}) &&
		bytes.Equal(buff[74:76], []byte{0x02, 0x00}) {

		// Vulnerability detected, log the result
		result := fmt.Sprintf("%v CVE-2020-0796 SmbGhost Vulnerable", ip)
		Common.LogSuccess(result)
	}

	return err
}

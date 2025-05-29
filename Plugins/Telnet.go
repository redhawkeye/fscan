package Plugins

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"net"
	"regexp"
	"strings"
	"time"
)

// TelnetScan performs Telnet service scanning and password brute-forcing
func TelnetScan(info *Common.HostInfo) (tmperr error) {
	if Common.DisableBrute {
		return
	}

	maxRetries := Common.MaxRetries
	target := fmt.Sprintf("%v:%v", info.Host, info.Ports)

	Common.LogDebug(fmt.Sprintf("Starting scan %s", target))
	totalUsers := len(Common.Userdict["telnet"])
	totalPass := len(Common.Passwords)
	Common.LogDebug(fmt.Sprintf("Starting username and password combinations (Total users: %d, Total passwords: %d)", totalUsers, totalPass))

	tried := 0
	total := totalUsers * totalPass

	// Iterate through all username and password combinations
	for _, user := range Common.Userdict["telnet"] {
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
					noAuth  bool
					err     error
				}, 1)

				go func(user, pass string) {
					flag, err := telnetConn(info, user, pass)
					select {
					case done <- struct {
						success bool
						noAuth  bool
						err     error
					}{err == nil, flag, err}:
					default:
					}
				}(user, pass)

				var err error
				select {
				case result := <-done:
					err = result.err
					if result.noAuth {
						// No authentication required
						msg := fmt.Sprintf("Telnet service %s does not require authentication", target)
						Common.LogSuccess(msg)

						// Save result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":    info.Ports,
								"service": "telnet",
								"type":    "unauthorized-access",
							},
						}
						Common.SaveResult(vulnResult)
						return nil

					} else if result.success {
						// Successful brute force
						msg := fmt.Sprintf("Telnet service %s username:%v password:%v", target, user, pass)
						Common.LogSuccess(msg)

						// Save result
						vulnResult := &Common.ScanResult{
							Time:   time.Now(),
							Type:   Common.VULN,
							Target: info.Host,
							Status: "vulnerable",
							Details: map[string]interface{}{
								"port":     info.Ports,
								"service":  "telnet",
								"type":     "weak-password",
								"username": user,
								"password": pass,
							},
						}
						Common.SaveResult(vulnResult)
						return nil
					}
				case <-time.After(time.Duration(Common.Timeout) * time.Second):
					err = fmt.Errorf("connection timeout")
				}

				if err != nil {
					errlog := fmt.Sprintf("Telnet connection failed %s username:%v password:%v error:%v",
						target, user, pass, err)
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

	Common.LogDebug(fmt.Sprintf("Scan complete, tried %d combinations", tried))
	return tmperr
}

// telnetConn attempts to establish a Telnet connection and perform authentication
func telnetConn(info *Common.HostInfo, user, pass string) (flag bool, err error) {
	client := NewTelnet(info.Host, info.Ports)

	if err = client.Connect(); err != nil {
		return false, err
	}
	defer client.Close()

	client.UserName = user
	client.Password = pass
	client.ServerType = client.MakeServerType()

	if client.ServerType == UnauthorizedAccess {
		return true, nil
	}

	err = client.Login()
	return false, err
}

const (
	// Delay after write operation
	TIME_DELAY_AFTER_WRITE = 300 * time.Millisecond

	// Telnet basic control characters
	IAC  = byte(255) // Interpret As Command
	DONT = byte(254) // Request the other party to stop executing an option
	DO   = byte(253) // Request the other party to execute an option
	WONT = byte(252) // Refuse to execute an option
	WILL = byte(251) // Agree to execute an option

	// Sub-negotiation related control characters
	SB = byte(250) // Subnegotiation Begin
	SE = byte(240) // Subnegotiation End

	// Special function characters
	NULL  = byte(0)   // Null character
	EOF   = byte(236) // End of file
	SUSP  = byte(237) // Suspend process
	ABORT = byte(238) // Abort process
	REOR  = byte(239) // End of record

	// Control operation characters
	NOP = byte(241) // No operation
	DM  = byte(242) // Data mark
	BRK = byte(243) // Break
	IP  = byte(244) // Interrupt process
	AO  = byte(245) // Abort output
	AYT = byte(246) // Are you there
	EC  = byte(247) // Erase character
	EL  = byte(248) // Erase line
	GA  = byte(249) // Go ahead

	// Telnet protocol option codes (from arpa/telnet.h)
	BINARY = byte(0) // 8-bit data path
	ECHO   = byte(1) // Echo
	RCP    = byte(2) // Prepare to reconnect
	SGA    = byte(3) // Suppress go ahead
	NAMS   = byte(4) // Approximate message size
	STATUS = byte(5) // Status query
	TM     = byte(6) // Timing mark
	RCTE   = byte(7) // Remote controlled transmission and echo

	// Output negotiation options
	NAOL   = byte(8)  // Output line width negotiation
	NAOP   = byte(9)  // Output page size negotiation
	NAOCRD = byte(10) // Carriage return disposition negotiation
	NAOHTS = byte(11) // Horizontal tab stop negotiation
	NAOHTD = byte(12) // Horizontal tab disposition negotiation
	NAOFFD = byte(13) // Form feed disposition negotiation
	NAOVTS = byte(14) // Vertical tab stop negotiation
	NAOVTD = byte(15) // Vertical tab disposition negotiation
	NAOLFD = byte(16) // Line feed disposition negotiation

	// Extended function options
	XASCII       = byte(17) // Extended ASCII character set
	LOGOUT       = byte(18) // Force logout
	BM           = byte(19) // Byte macro
	DET          = byte(20) // Data entry terminal
	SUPDUP       = byte(21) // SUPDUP protocol
	SUPDUPOUTPUT = byte(22) // SUPDUP output
	SNDLOC       = byte(23) // Send location

	// Terminal related options
	TTYPE        = byte(24) // Terminal type
	EOR          = byte(25) // End of record
	TUID         = byte(26) // TACACS user identification
	OUTMRK       = byte(27) // Output marking
	TTYLOC       = byte(28) // Terminal location number
	VT3270REGIME = byte(29) // 3270 regime

	// Communication control options
	X3PAD    = byte(30) // X.3 PAD
	NAWS     = byte(31) // Window size
	TSPEED   = byte(32) // Terminal speed
	LFLOW    = byte(33) // Remote flow control
	LINEMODE = byte(34) // Line mode option

	// Environment and authentication options
	XDISPLOC       = byte(35) // X display location
	OLD_ENVIRON    = byte(36) // Old environment variables
	AUTHENTICATION = byte(37) // Authentication
	ENCRYPT        = byte(38) // Encryption option
	NEW_ENVIRON    = byte(39) // New environment variables

	// Additional options assigned by IANA
	// http://www.iana.org/assignments/telnet-options
	TN3270E             = byte(40) // TN3270E
	XAUTH               = byte(41) // XAUTH
	CHARSET             = byte(42) // Character set
	RSP                 = byte(43) // Remote serial port
	COM_PORT_OPTION     = byte(44) // COM port control
	SUPPRESS_LOCAL_ECHO = byte(45) // Suppress local echo
	TLS                 = byte(46) // Start TLS
	KERMIT              = byte(47) // KERMIT protocol
	SEND_URL            = byte(48) // Send URL
	FORWARD_X           = byte(49) // X forwarding

	// Special purpose options
	PRAGMA_LOGON     = byte(138) // PRAGMA logon
	SSPI_LOGON       = byte(139) // SSPI logon
	PRAGMA_HEARTBEAT = byte(140) // PRAGMA heartbeat
	EXOPL            = byte(255) // Extended options list
	NOOPT            = byte(0)   // No option
)

// Server type constants
const (
	Closed              = iota // Connection closed
	UnauthorizedAccess         // No authentication required
	OnlyPassword               // Only password required
	UsernameAndPassword        // Username and password required
)

// TelnetClient Telnet client structure
type TelnetClient struct {
	IPAddr       string   // Server IP address
	Port         string   // Server port
	UserName     string   // Username
	Password     string   // Password
	conn         net.Conn // Network connection
	LastResponse string   // Last response content
	ServerType   int      // Server type
}

// NewTelnet creates a new Telnet client instance
func NewTelnet(addr, port string) *TelnetClient {
	return &TelnetClient{
		IPAddr:       addr,
		Port:         port,
		UserName:     "",
		Password:     "",
		conn:         nil,
		LastResponse: "",
		ServerType:   Closed,
	}
}

// Connect establishes a Telnet connection
func (c *TelnetClient) Connect() error {
	// Establish TCP connection with a timeout of 5 seconds
	conn, err := net.DialTimeout("tcp", c.Netloc(), 5*time.Second)
	if err != nil {
		return err
	}
	c.conn = conn

	// Start a background goroutine to handle server responses
	go func() {
		for {
			// Read server response
			buf, err := c.read()
			if err != nil {
				// Handle connection closed and EOF cases
				if strings.Contains(err.Error(), "closed") ||
					strings.Contains(err.Error(), "EOF") {
					break
				}
				break
			}

			// Process response data
			displayBuf, commandList := c.SerializationResponse(buf)

			if len(commandList) > 0 {
				// Commands need to be replied
				replyBuf := c.MakeReplyFromList(commandList)
				c.LastResponse += string(displayBuf)
				_ = c.write(replyBuf)
			} else {
				// Only save display content
				c.LastResponse += string(displayBuf)
			}
		}
	}()

	// Wait for connection initialization to complete
	time.Sleep(time.Second * 3)
	return nil
}

// WriteContext writes data to the Telnet connection
func (c *TelnetClient) WriteContext(s string) {
	// Write string and add carriage return and null character
	_ = c.write([]byte(s + "\x0d\x00"))
}

// ReadContext reads the content returned by the Telnet connection
func (c *TelnetClient) ReadContext() string {
	// Clear cache after reading
	defer func() { c.Clear() }()

	// Wait for response
	if c.LastResponse == "" {
		time.Sleep(time.Second)
	}

	// Handle special characters
	c.LastResponse = strings.ReplaceAll(c.LastResponse, "\x0d\x00", "")
	c.LastResponse = strings.ReplaceAll(c.LastResponse, "\x0d\x0a", "\n")

	return c.LastResponse
}

// Netloc gets the network address string
func (c *TelnetClient) Netloc() string {
	return fmt.Sprintf("%s:%s", c.IPAddr, c.Port)
}

// Close closes the Telnet connection
func (c *TelnetClient) Close() {
	c.conn.Close()
}

// SerializationResponse parses Telnet response data
func (c *TelnetClient) SerializationResponse(responseBuf []byte) (displayBuf []byte, commandList [][]byte) {
	for {
		// Find IAC command marker
		index := bytes.IndexByte(responseBuf, IAC)
		if index == -1 || len(responseBuf)-index < 2 {
			displayBuf = append(displayBuf, responseBuf...)
			break
		}

		// Get option character
		ch := responseBuf[index+1]

		// Handle consecutive IAC
		if ch == IAC {
			displayBuf = append(displayBuf, responseBuf[:index]...)
			responseBuf = responseBuf[index+1:]
			continue
		}

		// Handle DO/DONT/WILL/WONT commands
		if ch == DO || ch == DONT || ch == WILL || ch == WONT {
			commandBuf := responseBuf[index : index+3]
			commandList = append(commandList, commandBuf)
			displayBuf = append(displayBuf, responseBuf[:index]...)
			responseBuf = responseBuf[index+3:]
			continue
		}

		// Handle sub-negotiation commands
		if ch == SB {
			displayBuf = append(displayBuf, responseBuf[:index]...)
			seIndex := bytes.IndexByte(responseBuf, SE)
			commandList = append(commandList, responseBuf[index:seIndex])
			responseBuf = responseBuf[seIndex+1:]
			continue
		}

		break
	}

	return displayBuf, commandList
}

// MakeReplyFromList processes the command list and generates a reply
func (c *TelnetClient) MakeReplyFromList(list [][]byte) []byte {
	var reply []byte
	for _, command := range list {
		reply = append(reply, c.MakeReply(command)...)
	}
	return reply
}

// MakeReply generates a reply based on the command
func (c *TelnetClient) MakeReply(command []byte) []byte {
	// Command requires at least 3 bytes
	if len(command) < 3 {
		return []byte{}
	}

	verb := command[1]   // Action type
	option := command[2] // Option code

	// Handle ECHO and SGA options
	if option == ECHO || option == SGA {
		switch verb {
		case DO:
			return []byte{IAC, WILL, option}
		case DONT:
			return []byte{IAC, WONT, option}
		case WILL:
			return []byte{IAC, DO, option}
		case WONT:
			return []byte{IAC, DONT, option}
		case SB:
			// Handle sub-negotiation commands
			// Command format: IAC + SB + option + modifier + IAC + SE
			if len(command) >= 4 {
				modifier := command[3]
				if modifier == ECHO {
					return []byte{IAC, SB, option, BINARY, IAC, SE}
				}
			}
		}
	} else {
		// Handle other options - reject all requests
		switch verb {
		case DO, DONT:
			return []byte{IAC, WONT, option}
		case WILL, WONT:
			return []byte{IAC, DONT, option}
		}
	}

	return []byte{}
}

// read reads data from the Telnet connection
func (c *TelnetClient) read() ([]byte, error) {
	var buf [2048]byte
	n, err := c.conn.Read(buf[0:])
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// write writes data to the Telnet connection
func (c *TelnetClient) write(buf []byte) error {
	// Set write timeout
	_ = c.conn.SetWriteDeadline(time.Now().Add(time.Second * 3))

	_, err := c.conn.Write(buf)
	if err != nil {
		return err
	}
	return nil
}

// Login performs login based on the server type
func (c *TelnetClient) Login() error {
	switch c.ServerType {
	case Closed:
		return errors.New("service is disabled")
	case UnauthorizedAccess:
		return nil
	case OnlyPassword:
		return c.loginForOnlyPassword()
	case UsernameAndPassword:
		return c.loginForUsernameAndPassword()
	default:
		return errors.New("unknown server type")
	}
}

// MakeServerType determines the server type by analyzing the server response
func (c *TelnetClient) MakeServerType() int {
	responseString := c.ReadContext()
	response := strings.Split(responseString, "\n")
	lastLine := strings.ToLower(response[len(response)-1])

	// Check if username and password are required
	if containsAny(lastLine, []string{"user", "name", "login", "account", "username", "login"}) {
		return UsernameAndPassword
	}

	// Check if only password is required
	if strings.Contains(lastLine, "pass") {
		return OnlyPassword
	}

	// Check if no authentication is required
	if isNoAuthRequired(lastLine) || c.isLoginSucceed(responseString) {
		return UnauthorizedAccess
	}

	return Closed
}

// Helper function: checks if a string contains any given substrings
func containsAny(s string, substrings []string) bool {
	for _, sub := range substrings {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// Helper function: checks if no authentication is required
func isNoAuthRequired(line string) bool {
	patterns := []string{
		`^/ #.*`,
		`^<[A-Za-z0-9_]+>`,
		`^#`,
	}

	for _, pattern := range patterns {
		if regexp.MustCompile(pattern).MatchString(line) {
			return true
		}
	}
	return false
}

// loginForOnlyPassword handles login that requires only a password
func (c *TelnetClient) loginForOnlyPassword() error {
	c.Clear() // Clear previous response

	// Send password and wait for response
	c.WriteContext(c.Password)
	time.Sleep(time.Second * 3)

	// Verify login result
	responseString := c.ReadContext()
	if c.isLoginFailed(responseString) {
		return errors.New("login failed")
	}
	if c.isLoginSucceed(responseString) {
		return nil
	}

	return errors.New("login failed")
}

// loginForUsernameAndPassword handles login that requires both username and password
func (c *TelnetClient) loginForUsernameAndPassword() error {
	// Send username
	c.WriteContext(c.UserName)
	time.Sleep(time.Second * 3)
	c.Clear()

	// Send password
	c.WriteContext(c.Password)
	time.Sleep(time.Second * 5)

	// Verify login result
	responseString := c.ReadContext()
	if c.isLoginFailed(responseString) {
		return errors.New("login failed")
	}
	if c.isLoginSucceed(responseString) {
		return nil
	}

	return errors.New("login failed")
}

// Clear clears the last response
func (c *TelnetClient) Clear() {
	c.LastResponse = ""
}

// Keywords list for login failure
var loginFailedString = []string{
	"wrong",
	"invalid",
	"fail",
	"incorrect",
	"error",
}

// isLoginFailed checks if the login failed
func (c *TelnetClient) isLoginFailed(responseString string) bool {
	responseString = strings.ToLower(responseString)

	// Empty response is considered a failure
	if responseString == "" {
		return true
	}

	// Check failure keywords
	for _, str := range loginFailedString {
		if strings.Contains(responseString, str) {
			return true
		}
	}

	// Check if still asking for credentials
	patterns := []string{
		"(?is).*pass(word)?:$",
		"(?is).*user(name)?:$",
		"(?is).*login:$",
	}
	for _, pattern := range patterns {
		if regexp.MustCompile(pattern).MatchString(responseString) {
			return true
		}
	}

	return false
}

// isLoginSucceed checks if the login succeeded
func (c *TelnetClient) isLoginSucceed(responseString string) bool {
	// Get the last line of the response
	lines := strings.Split(responseString, "\n")
	lastLine := lines[len(lines)-1]

	// Check command prompt
	if regexp.MustCompile("^[#$].*").MatchString(lastLine) ||
		regexp.MustCompile("^<[a-zA-Z0-9_]+>.*").MatchString(lastLine) {
		return true
	}

	// Check last login information
	if regexp.MustCompile("(?:s)last login").MatchString(responseString) {
		return true
	}

	// Send test command to verify
	c.Clear()
	c.WriteContext("?")
	time.Sleep(time.Second * 3)
	responseString = c.ReadContext()

	// Check response length
	if strings.Count(responseString, "\n") > 6 || len([]rune(responseString)) > 100 {
		return true
	}

	return false
}

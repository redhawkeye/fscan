package Plugins

import (
	"errors"
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/rfb"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Brutelist represents a list of username and password combinations for brute force attacks
type Brutelist struct {
	user string
	pass string
}

// RdpScan performs a scan on RDP service
func RdpScan(info *Common.HostInfo) (tmperr error) {
	defer func() {
		recover()
	}()
	if Common.DisableBrute {
		return
	}

	port, _ := strconv.Atoi(info.Ports)
	total := len(Common.Userdict["rdp"]) * len(Common.Passwords)
	num := 0
	target := fmt.Sprintf("%v:%v", info.Host, port)

	// Iterate through username and password combinations
	for _, user := range Common.Userdict["rdp"] {
		for _, pass := range Common.Passwords {
			num++
			pass = strings.Replace(pass, "{user}", user, -1)

			// Attempt connection
			flag, err := RdpConn(info.Host, Common.Domain, user, pass, port, Common.Timeout)

			if flag && err == nil {
				// Connection successful
				var result string
				if Common.Domain != "" {
					result = fmt.Sprintf("RDP %v Domain: %v\\%v Password: %v", target, Common.Domain, user, pass)
				} else {
					result = fmt.Sprintf("RDP %v Username: %v Password: %v", target, user, pass)
				}
				Common.LogSuccess(result)

				// Save result
				details := map[string]interface{}{
					"port":     port,
					"service":  "rdp",
					"username": user,
					"password": pass,
					"type":     "weak-password",
				}
				if Common.Domain != "" {
					details["domain"] = Common.Domain
				}

				vulnResult := &Common.ScanResult{
					Time:    time.Now(),
					Type:    Common.VULN,
					Target:  info.Host,
					Status:  "vulnerable",
					Details: details,
				}
				Common.SaveResult(vulnResult)

				return nil
			}

			// Connection failed
			errlog := fmt.Sprintf("(%v/%v) RDP %v Username: %v Password: %v Error: %v",
				num, total, target, user, pass, err)
			Common.LogError(errlog)
		}
	}

	return tmperr
}

// RdpConn attempts to connect to RDP
func RdpConn(ip, domain, user, password string, port int, timeout int64) (bool, error) {
	defer func() {
		recover()
	}()
	target := fmt.Sprintf("%s:%d", ip, port)

	// Create RDP client
	client := NewClient(target, glog.NONE)
	if err := client.Login(domain, user, password, timeout); err != nil {
		return false, err
	}

	return true, nil
}

// Client represents an RDP client
type Client struct {
	Host string          // Server address (ip:port)
	tpkt *tpkt.TPKT      // TPKT protocol layer
	x224 *x224.X224      // X224 protocol layer
	mcs  *t125.MCSClient // MCS protocol layer
	sec  *sec.Client     // Security layer
	pdu  *pdu.Client     // PDU protocol layer
	vnc  *rfb.RFB        // VNC protocol (optional)
}

// NewClient creates a new RDP client
func NewClient(host string, logLevel glog.LEVEL) *Client {
	// Configure logging
	glog.SetLevel(logLevel)
	logger := log.New(os.Stdout, "", 0)
	glog.SetLogger(logger)

	return &Client{
		Host: host,
	}
}

// Login performs RDP login
func (g *Client) Login(domain, user, pwd string, timeout int64) error {
	// Establish TCP connection
	conn, err := Common.WrapperTcpWithTimeout("tcp", g.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("[Connection error] %v", err)
	}
	defer conn.Close()
	glog.Info(conn.LocalAddr().String())

	// Initialize protocol stack
	g.initProtocolStack(conn, domain, user, pwd)

	// Establish X224 connection
	if err = g.x224.Connect(); err != nil {
		return fmt.Errorf("[X224 connection error] %v", err)
	}
	glog.Info("Waiting for connection to be established...")

	// Wait for connection to complete
	wg := &sync.WaitGroup{}
	breakFlag := false
	wg.Add(1)

	// Set event handlers
	g.setupEventHandlers(wg, &breakFlag, &err)

	wg.Wait()
	return err
}

// initProtocolStack initializes the RDP protocol stack
func (g *Client) initProtocolStack(conn net.Conn, domain, user, pwd string) {
	// Create protocol layer instances
	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	// Set authentication information
	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)

	// Configure protocol layer associations
	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)
}

// setupEventHandlers sets up PDU event handlers
func (g *Client) setupEventHandlers(wg *sync.WaitGroup, breakFlag *bool, err *error) {
	// Error handling
	g.pdu.On("error", func(e error) {
		*err = e
		glog.Error("Error:", e)
		g.pdu.Emit("done")
	})

	// Connection closed
	g.pdu.On("close", func() {
		*err = errors.New("Connection closed")
		glog.Info("Connection closed")
		g.pdu.Emit("done")
	})

	// Connection successful
	g.pdu.On("success", func() {
		*err = nil
		glog.Info("Connection successful")
		g.pdu.Emit("done")
	})

	// Connection ready
	g.pdu.On("ready", func() {
		glog.Info("Connection ready")
		g.pdu.Emit("done")
	})

	// Screen update
	g.pdu.On("update", func(rectangles []pdu.BitmapData) {
		glog.Info("Screen update:", rectangles)
	})

	// Completion handling
	g.pdu.On("done", func() {
		if !*breakFlag {
			*breakFlag = true
			wg.Done()
		}
	})
}

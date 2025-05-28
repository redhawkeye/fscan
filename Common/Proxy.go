package Common

import (
	"errors"
	"fmt"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"strings"
	"time"
)

// WrapperTcpWithTimeout creates a TCP connection with a timeout
func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return WrapperTCP(network, address, d)
}

// WrapperTCP creates a TCP connection based on the configuration
func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	// Direct connection mode
	if Socks5Proxy == "" {
		conn, err := forward.Dial(network, address)
		if err != nil {
			return nil, fmt.Errorf(GetText("tcp_conn_failed"), err)
		}
		return conn, nil
	}

	// Socks5 proxy mode
	dialer, err := Socks5Dialer(forward)
	if err != nil {
		return nil, fmt.Errorf(GetText("socks5_create_failed"), err)
	}

	conn, err := dialer.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf(GetText("socks5_conn_failed"), err)
	}

	return conn, nil
}

// Socks5Dialer creates a Socks5 proxy dialer
func Socks5Dialer(forward *net.Dialer) (proxy.Dialer, error) {
	// Parse proxy URL
	u, err := url.Parse(Socks5Proxy)
	if err != nil {
		return nil, fmt.Errorf(GetText("socks5_parse_failed"), err)
	}

	// Validate proxy type
	if strings.ToLower(u.Scheme) != "socks5" {
		return nil, errors.New(GetText("socks5_only"))
	}

	address := u.Host
	var dialer proxy.Dialer

	// Create proxy based on authentication information
	if u.User.String() != "" {
		// Use username and password authentication
		auth := proxy.Auth{
			User: u.User.Username(),
		}
		auth.Password, _ = u.User.Password()
		dialer, err = proxy.SOCKS5("tcp", address, &auth, forward)
	} else {
		// No authentication mode
		dialer, err = proxy.SOCKS5("tcp", address, nil, forward)
	}

	if err != nil {
		return nil, fmt.Errorf(GetText("socks5_create_failed"), err)
	}

	return dialer, nil
}

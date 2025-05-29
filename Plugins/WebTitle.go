package Plugins

import (
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shadow1ng/fscan/Common"
	"github.com/shadow1ng/fscan/WebScan"
	"github.com/shadow1ng/fscan/WebScan/lib"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// WebTitle Get Web title and fingerprint information
func WebTitle(info *Common.HostInfo) error {
	Common.LogDebug(fmt.Sprintf("Start getting Web title, initial information: %+v", info))

	// Get website title information
	err, CheckData := GOWebTitle(info)
	Common.LogDebug(fmt.Sprintf("GOWebTitle execution completed - Error: %v, Check data length: %d", err, len(CheckData)))

	info.Infostr = WebScan.InfoCheck(info.Url, &CheckData)
	Common.LogDebug(fmt.Sprintf("Information check completed, obtained information: %v", info.Infostr))

	// Check if it is a printer to avoid accidental printing
	for _, v := range info.Infostr {
		if v == "Printer" {
			Common.LogDebug("Printer detected, stopping scan")
			return nil
		}
	}

	// Output error message (if any)
	if err != nil {
		errlog := fmt.Sprintf("Website title %v %v", info.Url, err)
		Common.LogError(errlog)
	}

	return err
}

// GOWebTitle Get website title and process URL
func GOWebTitle(info *Common.HostInfo) (err error, CheckData []WebScan.CheckDatas) {
	Common.LogDebug(fmt.Sprintf("Start processing URL: %s", info.Url))

	// If URL is not specified, generate URL based on port
	if info.Url == "" {
		Common.LogDebug("URL is empty, generating URL based on port")
		switch info.Ports {
		case "80":
			info.Url = fmt.Sprintf("http://%s", info.Host)
		case "443":
			info.Url = fmt.Sprintf("https://%s", info.Host)
		default:
			host := fmt.Sprintf("%s:%s", info.Host, info.Ports)
			Common.LogDebug(fmt.Sprintf("Detecting host protocol: %s", host))
			protocol := GetProtocol(host, Common.Timeout)
			Common.LogDebug(fmt.Sprintf("Detected protocol: %s", protocol))
			info.Url = fmt.Sprintf("%s://%s:%s", protocol, info.Host, info.Ports)
		}
	} else {
		// Process URL without specified protocol
		if !strings.Contains(info.Url, "://") {
			Common.LogDebug("URL does not contain protocol, start detecting")
			host := strings.Split(info.Url, "/")[0]
			protocol := GetProtocol(host, Common.Timeout)
			Common.LogDebug(fmt.Sprintf("Detected protocol: %s", protocol))
			info.Url = fmt.Sprintf("%s://%s", protocol, info.Url)
		}
	}
	Common.LogDebug(fmt.Sprintf("URL after protocol detection: %s", info.Url))

	// First attempt to get URL
	Common.LogDebug("First attempt to access URL")
	err, result, CheckData := geturl(info, 1, CheckData)
	Common.LogDebug(fmt.Sprintf("First access result - Error: %v, Return information: %s", err, result))
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return
	}

	// Process URL redirection
	if strings.Contains(result, "://") {
		Common.LogDebug(fmt.Sprintf("Detected redirection to: %s", result))
		info.Url = result
		err, result, CheckData = geturl(info, 3, CheckData)
		Common.LogDebug(fmt.Sprintf("Redirection request result - Error: %v, Return information: %s", err, result))
		if err != nil {
			return
		}
	}

	// Process HTTP to HTTPS upgrade
	if result == "https" && !strings.HasPrefix(info.Url, "https://") {
		Common.LogDebug("Upgrading to HTTPS")
		info.Url = strings.Replace(info.Url, "http://", "https://", 1)
		Common.LogDebug(fmt.Sprintf("URL after upgrade: %s", info.Url))
		err, result, CheckData = geturl(info, 1, CheckData)

		// Process redirection after upgrade
		if strings.Contains(result, "://") {
			Common.LogDebug(fmt.Sprintf("Redirection detected after HTTPS upgrade to: %s", result))
			info.Url = result
			err, _, CheckData = geturl(info, 3, CheckData)
			if err != nil {
				return
				}
			}
		}

	Common.LogDebug(fmt.Sprintf("GOWebTitle execution completed - Error: %v", err))
	if err != nil {
		return
	}
	return
}

func geturl(info *Common.HostInfo, flag int, CheckData []WebScan.CheckDatas) (error, string, []WebScan.CheckDatas) {
	Common.LogDebug(fmt.Sprintf("geturl execution started - URL: %s, Flag: %d", info.Url, flag))

	// Process target URL
	Url := info.Url
	if flag == 2 {
		Common.LogDebug("Processing favicon.ico URL")
		URL, err := url.Parse(Url)
		if err == nil {
			Url = fmt.Sprintf("%s://%s/favicon.ico", URL.Scheme, URL.Host)
		} else {
			Url += "/favicon.ico"
		}
		Common.LogDebug(fmt.Sprintf("favicon URL: %s", Url))
	}

	// Create HTTP request
	Common.LogDebug("Start creating HTTP request")
	req, err := http.NewRequest("GET", Url, nil)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("Failed to create HTTP request: %v", err))
		return err, "", CheckData
	}

	// Set request headers
	req.Header.Set("User-agent", Common.UserAgent)
	req.Header.Set("Accept", Common.Accept)
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	if Common.Cookie != "" {
		req.Header.Set("Cookie", Common.Cookie)
	}
	req.Header.Set("Connection", "close")
	Common.LogDebug("Request headers set")

	// Choose HTTP client
	var client *http.Client
	if flag == 1 {
		client = lib.ClientNoRedirect
		Common.LogDebug("Using client without following redirects")
	} else {
		client = lib.Client
		Common.LogDebug("Using regular client")
	}

	// Check if client is nil
	if client == nil {
		Common.LogDebug("Error: HTTP client is nil")
		return fmt.Errorf("HTTP client not initialized"), "", CheckData
	}

	// Send request
	Common.LogDebug("Start sending HTTP request")
	resp, err := client.Do(req)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("HTTP request failed: %v", err))
		return err, "https", CheckData
	}
	defer resp.Body.Close()
	Common.LogDebug(fmt.Sprintf("Received HTTP response, status code: %d", resp.StatusCode))

	// Read response content
	body, err := getRespBody(resp)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("Failed to read response content: %v", err))
		return err, "https", CheckData
	}
	Common.LogDebug(fmt.Sprintf("Successfully read response content, length: %d", len(body)))

	// Save check data
	CheckData = append(CheckData, WebScan.CheckDatas{body, fmt.Sprintf("%s", resp.Header)})
	Common.LogDebug("Check data saved")

	// Process non-favicon request
	var reurl string
	if flag != 2 {
		// Process encoding
		if !utf8.Valid(body) {
			body, _ = simplifiedchinese.GBK.NewDecoder().Bytes(body)
		}

		// Get page information
		title := gettitle(body)
		length := resp.Header.Get("Content-Length")
		if length == "" {
			length = fmt.Sprintf("%v", len(body))
		}

		// Collect server information
		serverInfo := make(map[string]interface{})
		serverInfo["title"] = title
		serverInfo["length"] = length
		serverInfo["status_code"] = resp.StatusCode

		// Collect response header information
		for k, v := range resp.Header {
			if len(v) > 0 {
				serverInfo[strings.ToLower(k)] = v[0]
			}
		}

		// Check for redirection
		redirURL, err1 := resp.Location()
		if err1 == nil {
			reurl = redirURL.String()
			serverInfo["redirect_url"] = reurl
		}

		// Save scan result
		result := &Common.ScanResult{
			Time:   time.Now(),
			Type:   Common.SERVICE,
			Target: info.Host,
			Status: "identified",
			Details: map[string]interface{}{
				"port":         info.Ports,
				"service":      "http",
				"title":        title,
				"url":          resp.Request.URL.String(),
				"status_code":  resp.StatusCode,
				"length":       length,
				"server_info":  serverInfo,
				"fingerprints": info.Infostr, // Fingerprint information
			},
		}
		Common.SaveResult(result)

		// Output console log
		logMsg := fmt.Sprintf("Website title %-25v Status code:%-3v Length:%-6v Title:%v",
			resp.Request.URL, resp.StatusCode, length, title)
		if reurl != "" {
			logMsg += fmt.Sprintf(" Redirect URL: %s", reurl)
		}
		Common.LogSuccess(logMsg)
	}

	// Return result
	if reurl != "" {
		Common.LogDebug(fmt.Sprintf("Returning redirect URL: %s", reurl))
		return nil, reurl, CheckData
	}
	if resp.StatusCode == 400 && !strings.HasPrefix(info.Url, "https") {
		Common.LogDebug("Returning HTTPS upgrade flag")
		return nil, "https", CheckData
	}
	Common.LogDebug("geturl execution completed, no special return")
	return nil, "", CheckData
}

// getRespBody Read HTTP response body content
func getRespBody(oResp *http.Response) ([]byte, error) {
	Common.LogDebug("Start reading response body content")
	var body []byte

	// Process gzip compressed response
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		Common.LogDebug("Detected gzip compression, start decompressing")
		gr, err := gzip.NewReader(oResp.Body)
		if err != nil {
			Common.LogDebug(fmt.Sprintf("Failed to create gzip decompressor: %v", err))
			return nil, err
		}
		defer gr.Close()

		// Loop to read decompressed content
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				Common.LogDebug(fmt.Sprintf("Failed to read compressed content: %v", err))
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
		Common.LogDebug(fmt.Sprintf("gzip decompression completed, content length: %d", len(body)))
	} else {
		// Directly read uncompressed response
		Common.LogDebug("Reading uncompressed response content")
		raw, err := io.ReadAll(oResp.Body)
		if err != nil {
			Common.LogDebug(fmt.Sprintf("Failed to read response content: %v", err))
			return nil, err
		}
		body = raw
		Common.LogDebug(fmt.Sprintf("Reading completed, content length: %d", len(body)))
	}
	return body, nil
}

// gettitle Extract web page title from HTML content
func gettitle(body []byte) (title string) {
	Common.LogDebug("Start extracting web page title")

	// Use regular expression to match title tag content
	re := regexp.MustCompile("(?ims)<title.*?>(.*?)</title>")
	find := re.FindSubmatch(body)

	if len(find) > 1 {
		title = string(find[1])
		Common.LogDebug(fmt.Sprintf("Found original title: %s", title))

		// Clean title content
		title = strings.TrimSpace(title)                  // Remove leading and trailing spaces
		title = strings.Replace(title, "\n", "", -1)      // Remove newlines
		title = strings.Replace(title, "\r", "", -1)      // Remove carriage returns
		title = strings.Replace(title, "&nbsp;", " ", -1) // Replace HTML spaces

		// Truncate overly long titles
		if len(title) > 100 {
			Common.LogDebug("Title exceeds 100 characters, truncating")
			title = title[:100]
		}

		// Handle empty titles
		if title == "" {
			Common.LogDebug("Title is empty, using double quotes instead")
			title = "\"\""
		}
	} else {
		Common.LogDebug("Title tag not found")
		title = "No title"
	}
	Common.LogDebug(fmt.Sprintf("Final title: %s", title))
	return
}

// GetProtocol Detect the protocol type (HTTP/HTTPS) of the target host
func GetProtocol(host string, Timeout int64) (protocol string) {
	Common.LogDebug(fmt.Sprintf("Start detecting host protocol - Host: %s, Timeout: %d seconds", host, Timeout))
	protocol = "http"

	// Quickly determine protocol based on standard ports
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		Common.LogDebug("Detected HTTP standard port or no port, using HTTP protocol")
		return
	} else if strings.HasSuffix(host, ":443") {
		Common.LogDebug("Detected HTTPS standard port, using HTTPS protocol")
		protocol = "https"
		return
	}

	// Attempt to establish TCP connection
	Common.LogDebug("Attempting to establish TCP connection")
	socksconn, err := Common.WrapperTcpWithTimeout("tcp", host, time.Duration(Timeout)*time.Second)
	if err != nil {
		Common.LogDebug(fmt.Sprintf("TCP connection failed: %v", err))
		return
	}

	// Attempt TLS handshake
	Common.LogDebug("Start TLS handshake")
	conn := tls.Client(socksconn, &tls.Config{
		MinVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
	})

	// Ensure connection is closed
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
					Common.LogError(fmt.Sprintf("Error occurred while closing connection: %v", err))
				}
			}()
			Common.LogDebug("Closing connection")
			conn.Close()
		}
	}()

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))

	// Perform TLS handshake
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		Common.LogDebug("TLS handshake successful or handshake failed but confirmed to be HTTPS protocol")
		protocol = "https"
	} else {
		Common.LogDebug(fmt.Sprintf("TLS handshake failed: %v, using HTTP protocol", err))
	}

	Common.LogDebug(fmt.Sprintf("Protocol detection completed, using: %s", protocol))
	return protocol
}

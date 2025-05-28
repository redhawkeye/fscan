package Common

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func Parse(Info *HostInfo) error {
	ParseUser()
	ParsePass(Info)
	if err := ParseInput(Info); err != nil {
		return err
	}
	return nil
}

// ParseUser parses the username configuration
func ParseUser() error {
	// If no username and username file are specified, return directly
	if Username == "" && UsersFile == "" {
		return nil
	}

	var usernames []string

	// Handle directly specified username list
	if Username != "" {
		usernames = strings.Split(Username, ",")
		LogInfo(GetText("no_username_specified", len(usernames)))
	}

	// Load username list from file
	if UsersFile != "" {
		users, err := Readfile(UsersFile)
		if err != nil {
			return fmt.Errorf("Failed to read username file: %v", err)
		}

		// Filter out empty usernames
		for _, user := range users {
			if user != "" {
				usernames = append(usernames, user)
			}
		}
		LogInfo(GetText("load_usernames_from_file", len(users)))
	}

	// Remove duplicates
	usernames = RemoveDuplicate(usernames)
	LogInfo(GetText("total_usernames", len(usernames)))

	// Update user dictionary
	for name := range Userdict {
		Userdict[name] = usernames
	}

	return nil
}

// ParsePass parses passwords, hashes, URLs, and port configurations
func ParsePass(Info *HostInfo) error {
	// Handle directly specified password list
	var pwdList []string
	if Password != "" {
		passes := strings.Split(Password, ",")
		for _, pass := range passes {
			if pass != "" {
				pwdList = append(pwdList, pass)
			}
		}
		Passwords = pwdList
		LogInfo(GetText("load_passwords", len(pwdList)))
	}

	// Load password list from file
	if PasswordsFile != "" {
		passes, err := Readfile(PasswordsFile)
		if err != nil {
			return fmt.Errorf("Failed to read password file: %v", err)
		}
		for _, pass := range passes {
			if pass != "" {
				pwdList = append(pwdList, pass)
			}
			Passwords = pwdList
		}
		LogInfo(GetText("load_passwords_from_file", len(passes)))
	}

	// Handle hash file
	if HashFile != "" {
		hashes, err := Readfile(HashFile)
		if err != nil {
			return fmt.Errorf("Failed to read hash file: %v", err)
		}

		validCount := 0
		for _, line := range hashes {
			if line == "" {
				continue
			}
			if len(line) == 32 {
				HashValues = append(HashValues, line)
				validCount++
			} else {
				LogError(GetText("invalid_hash", line))
			}
		}
		LogInfo(GetText("load_valid_hashes", validCount))
	}

	// Handle directly specified URL list
	if TargetURL != "" {
		urls := strings.Split(TargetURL, ",")
		tmpUrls := make(map[string]struct{})
		for _, url := range urls {
			if url != "" {
				if _, ok := tmpUrls[url]; !ok {
					tmpUrls[url] = struct{}{}
					URLs = append(URLs, url)
				}
			}
		}
		LogInfo(GetText("load_urls", len(URLs)))
	}

	// Load URL list from file
	if URLsFile != "" {
		urls, err := Readfile(URLsFile)
		if err != nil {
			return fmt.Errorf("Failed to read URL file: %v", err)
		}

		tmpUrls := make(map[string]struct{})
		for _, url := range urls {
			if url != "" {
				if _, ok := tmpUrls[url]; !ok {
					tmpUrls[url] = struct{}{}
					URLs = append(URLs, url)
				}
			}
		}
		LogInfo(GetText("load_urls_from_file", len(urls)))
	}

	// Load host list from file
	if HostsFile != "" {
		hosts, err := Readfile(HostsFile)
		if err != nil {
			return fmt.Errorf("Failed to read host file: %v", err)
		}

		tmpHosts := make(map[string]struct{})
		for _, host := range hosts {
			if host != "" {
				if _, ok := tmpHosts[host]; !ok {
					tmpHosts[host] = struct{}{}
					if Info.Host == "" {
						Info.Host = host
					} else {
						Info.Host += "," + host
					}
				}
			}
		}
		LogInfo(GetText("load_hosts_from_file", len(hosts)))
	}

	// Load port list from file
	if PortsFile != "" {
		ports, err := Readfile(PortsFile)
		if err != nil {
			return fmt.Errorf("Failed to read port file: %v", err)
		}

		var newport strings.Builder
		for _, port := range ports {
			if port != "" {
				newport.WriteString(port)
				newport.WriteString(",")
			}
		}
		Ports = newport.String()
		LogInfo(GetText("load_ports_from_file"))
	}

	return nil
}

// Readfile reads the content of a file and returns a slice of non-empty lines
func Readfile(filename string) ([]string, error) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		LogError(GetText("open_file_failed", filename, err))
		return nil, err
	}
	defer file.Close()

	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	// Read the file line by line
	lineCount := 0
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			content = append(content, text)
			lineCount++
		}
	}

	// Check for errors during scanning
	if err := scanner.Err(); err != nil {
		LogError(GetText("read_file_failed", filename, err))
		return nil, err
	}

	LogInfo(GetText("read_file_success", filename, lineCount))
	return content, nil
}

// ParseInput parses and validates input parameter configurations
func ParseInput(Info *HostInfo) error {
	// Check for mutually exclusive scan modes
	modes := 0
	if Info.Host != "" || HostsFile != "" {
		modes++
	}
	if TargetURL != "" || URLsFile != "" {
		modes++
	}
	if LocalMode {
		modes++
	}

	if modes == 0 {
		// Show help when no parameters are provided
		flag.Usage()
		return fmt.Errorf(GetText("specify_scan_params"))
	} else if modes > 1 {
		return fmt.Errorf(GetText("params_conflict"))
	}

	// Handle brute force thread configuration
	if BruteThreads <= 0 {
		BruteThreads = 1
		LogInfo(GetText("brute_threads", BruteThreads))
	}

	// Handle port configuration
	if Ports == MainPorts {
		Ports += "," + WebPorts
	}

	if AddPorts != "" {
		if strings.HasSuffix(Ports, ",") {
			Ports += AddPorts
		} else {
			Ports += "," + AddPorts
		}
		LogInfo(GetText("extra_ports", AddPorts))
	}

	// Handle username configuration
	if AddUsers != "" {
		users := strings.Split(AddUsers, ",")
		for dict := range Userdict {
			Userdict[dict] = append(Userdict[dict], users...)
			Userdict[dict] = RemoveDuplicate(Userdict[dict])
		}
		LogInfo(GetText("extra_usernames", AddUsers))
	}

	// Handle password configuration
	if AddPasswords != "" {
		passes := strings.Split(AddPasswords, ",")
		Passwords = append(Passwords, passes...)
		Passwords = RemoveDuplicate(Passwords)
		LogInfo(GetText("extra_passwords", AddPasswords))
	}

	// Handle Socks5 proxy configuration
	if Socks5Proxy != "" {
		if !strings.HasPrefix(Socks5Proxy, "socks5://") {
			if !strings.Contains(Socks5Proxy, ":") {
				Socks5Proxy = "socks5://127.0.0.1" + Socks5Proxy
			} else {
				Socks5Proxy = "socks5://" + Socks5Proxy
			}
		}

		_, err := url.Parse(Socks5Proxy)
		if err != nil {
			return fmt.Errorf(GetText("socks5_proxy_error", err))
		}
		DisablePing = true
		LogInfo(GetText("socks5_proxy", Socks5Proxy))
	}

	// Handle HTTP proxy configuration
	if HttpProxy != "" {
		switch HttpProxy {
		case "1":
			HttpProxy = "http://127.0.0.1:8080"
		case "2":
			HttpProxy = "socks5://127.0.0.1:1080"
		default:
			if !strings.Contains(HttpProxy, "://") {
				HttpProxy = "http://127.0.0.1:" + HttpProxy
			}
		}

		if !strings.HasPrefix(HttpProxy, "socks") && !strings.HasPrefix(HttpProxy, "http") {
			return fmt.Errorf(GetText("unsupported_proxy"))
		}

		_, err := url.Parse(HttpProxy)
		if err != nil {
			return fmt.Errorf(GetText("proxy_format_error", err))
		}
		LogInfo(GetText("http_proxy", HttpProxy))
	}

	// Handle Hash configuration
	if HashValue != "" {
		if len(HashValue) != 32 {
			return fmt.Errorf(GetText("hash_length_error"))
		}
		HashValues = append(HashValues, HashValue)
	}

	// Handle Hash list
	HashValues = RemoveDuplicate(HashValues)
	for _, hash := range HashValues {
		hashByte, err := hex.DecodeString(hash)
		if err != nil {
			LogError(GetText("hash_decode_failed", hash))
			continue
		}
		HashBytes = append(HashBytes, hashByte)
	}
	HashValues = []string{}

	return nil
}

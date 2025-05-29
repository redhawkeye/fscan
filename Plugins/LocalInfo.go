package Plugins

import (
	"fmt"
	"github.com/shadow1ng/fscan/Common"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	// File scan blacklist, skip these types and directories
	blacklist = []string{
		".exe", ".dll", ".png", ".jpg", ".bmp", ".xml", ".bin",
		".dat", ".manifest", "locale", "winsxs", "windows\\sys",
	}

	// Sensitive file keyword whitelist
	whitelist = []string{
		"password", "account", "configuration", "server",
		"database", "memo", "common", "contacts",
	}

	// Linux system key configuration file paths
	linuxSystemPaths = []string{
		// Apache configuration
		"/etc/apache/httpd.conf",
		"/etc/httpd/conf/httpd.conf",
		"/etc/httpd/httpd.conf",
		"/usr/local/apache/conf/httpd.conf",
		"/home/httpd/conf/httpd.conf",
		"/usr/local/apache2/conf/httpd.conf",
		"/usr/local/httpd/conf/httpd.conf",
		"/etc/apache2/sites-available/000-default.conf",
		"/etc/apache2/sites-enabled/*",
		"/etc/apache2/sites-available/*",
		"/etc/apache2/apache2.conf",

		// Nginx configuration
		"/etc/nginx/nginx.conf",
		"/etc/nginx/conf.d/nginx.conf",

		// System configuration files
		"/etc/hosts.deny",
		"/etc/bashrc",
		"/etc/issue",
		"/etc/issue.net",
		"/etc/ssh/ssh_config",
		"/etc/termcap",
		"/etc/xinetd.d/*",
		"/etc/mtab",
		"/etc/vsftpd/vsftpd.conf",
		"/etc/xinetd.conf",
		"/etc/protocols",
		"/etc/logrotate.conf",
		"/etc/ld.so.conf",
		"/etc/resolv.conf",
		"/etc/sysconfig/network",
		"/etc/sendmail.cf",
		"/etc/sendmail.cw",

		// proc information
		"/proc/mounts",
		"/proc/cpuinfo",
		"/proc/meminfo",
		"/proc/self/environ",
		"/proc/1/cmdline",
		"/proc/1/mountinfo",
		"/proc/1/fd/*",
		"/proc/1/exe",
		"/proc/config.gz",

		// User configuration files
		"/root/.ssh/authorized_keys",
		"/root/.ssh/id_rsa",
		"/root/.ssh/id_rsa.keystore",
		"/root/.ssh/id_rsa.pub",
		"/root/.ssh/known_hosts",
		"/root/.bash_history",
		"/root/.mysql_history",
	}

	// Windows system key configuration file paths
	windowsSystemPaths = []string{
		"C:\\boot.ini",
		"C:\\windows\\systems32\\inetsrv\\MetaBase.xml",
		"C:\\windows\\repair\\sam",
		"C:\\windows\\system32\\config\\sam",
	}
)

// LocalInfoScan main function for local information collection
func LocalInfoScan(info *Common.HostInfo) (err error) {
	Common.LogInfo("Starting local information collection...")
	
	// Get user home directory
	home, err := os.UserHomeDir()
	if err != nil {
		Common.LogError(fmt.Sprintf("Failed to get user home directory: %v", err))
		return err
	}

	// Scan sensitive files in fixed locations
	scanFixedLocations(home)

	// Search for sensitive files based on rules
	searchSensitiveFiles()

	Common.LogInfo("Local information collection completed")
	return nil
}

// scanFixedLocations scans sensitive files in fixed locations
func scanFixedLocations(home string) {
	var paths []string

	switch runtime.GOOS {
	case "windows":
		// Add Windows fixed paths
		paths = append(paths, windowsSystemPaths...)
		paths = append(paths, []string{
			filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data"),
			filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data", "Local State"),
			filepath.Join(home, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Login Data"),
			filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
		}...)

	case "linux":
		// Add Linux fixed paths
		paths = append(paths, linuxSystemPaths...)
		paths = append(paths, []string{
			filepath.Join(home, ".config", "google-chrome", "Default", "Login Data"),
			filepath.Join(home, ".mozilla", "firefox"),
		}...)
	}

	for _, path := range paths {
		// Handle wildcard paths
		if strings.Contains(path, "*") {
			var _ = strings.ReplaceAll(path, "*", "")
			if files, err := filepath.Glob(path); err == nil {
				for _, file := range files {
					checkAndLogFile(file)
				}
			}
			continue
		}

		checkAndLogFile(path)
	}
}

// checkAndLogFile checks and logs sensitive files
func checkAndLogFile(path string) {
	if _, err := os.Stat(path); err == nil {
		Common.LogSuccess(fmt.Sprintf("Found sensitive file: %s", path))
	}
}

// searchSensitiveFiles searches for sensitive files
func searchSensitiveFiles() {
	var searchPaths []string

	switch runtime.GOOS {
	case "windows":
		// Common sensitive directories in Windows
		home, _ := os.UserHomeDir()
		searchPaths = []string{
			"C:\\Users\\Public\\Documents",
			"C:\\Users\\Public\\Desktop",
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Downloads"),
			"C:\\Program Files",
			"C:\\Program Files (x86)",
		}
	case "linux":
		// Common sensitive directories in Linux
		home, _ := os.UserHomeDir()
		searchPaths = []string{
			"/home",
			"/opt",
			"/usr/local",
			"/var/www",
			"/var/log",
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Downloads"),
		}
	}

	// Search within limited directories
	for _, searchPath := range searchPaths {
		filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Skip blacklist directories and files
			for _, black := range blacklist {
				if strings.Contains(strings.ToLower(path), black) {
					return filepath.SkipDir
				}
			}

			// Check whitelist keywords
			for _, white := range whitelist {
				fileName := strings.ToLower(info.Name())
				if strings.Contains(fileName, white) {
					Common.LogSuccess(fmt.Sprintf("Found potential sensitive file: %s", path))
					break
				}
			}
			return nil
		})
	}
}

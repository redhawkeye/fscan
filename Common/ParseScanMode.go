package Common

// Scan mode constants - Using uppercase to indicate this is a preset scan mode
const (
	ModeAll      = "All"      // Full scan
	ModeBasic    = "Basic"    // Basic scan
	ModeDatabase = "Database" // Database scan
	ModeWeb      = "Web"      // Web scan
	ModeService  = "Service"  // Service scan
	ModeVul      = "Vul"      // Vulnerability scan
	ModePort     = "Port"     // Port scan
	ModeICMP     = "ICMP"     // ICMP probe
	ModeLocal    = "Local"    // Local information gathering
)

// Plugin category mapping table - All plugin names use lowercase
var PluginGroups = map[string][]string{
	ModeAll: {
		"webtitle", "webpoc", // web category
		"mysql", "mssql", "redis", "mongodb", "postgres", // database category
		"oracle", "memcached", "elasticsearch", "rabbitmq", "kafka", "activemq", "cassandra", "neo4j", // database category
		"ftp", "ssh", "telnet", "smb", "rdp", "vnc", "netbios", "ldap", "smtp", "imap", "pop3", "snmp", "modbus", "rsync", // service category
		"ms17010", "smbghost", "smb2", // vulnerability category
		"findnet", // other
	},
	ModeBasic: {
		"webtitle", "ftp", "ssh", "smb", "findnet",
	},
	ModeDatabase: {
		"mysql", "mssql", "redis", "mongodb",
		"postgres", "oracle", "memcached", "elasticsearch", "rabbitmq", "kafka", "activemq", "cassandra", "neo4j",
	},
	ModeWeb: {
		"webtitle", "webpoc",
	},
	ModeService: {
		"ftp", "ssh", "telnet", "smb", "rdp", "vnc", "netbios", "ldap", "smtp", "imap", "pop3", "modbus", "rsync",
	},
	ModeVul: {
		"ms17010", "smbghost", "smb2",
	},
	ModeLocal: {
		"localinfo", "minidump", "dcinfo",
	},
}

// ParseScanMode parses the scan mode
func ParseScanMode(mode string) {
	LogInfo(GetText("parse_scan_mode", mode))

	// Check if it is a preset mode
	presetModes := []string{
		ModeAll, ModeBasic, ModeDatabase, ModeWeb,
		ModeService, ModeVul, ModePort, ModeICMP, ModeLocal,
	}

	for _, presetMode := range presetModes {
		if mode == presetMode {
			ScanMode = mode
			if plugins := GetPluginsForMode(mode); plugins != nil {
				LogInfo(GetText("using_preset_mode_plugins", mode, plugins))
			} else {
				LogInfo(GetText("using_preset_mode", mode))
			}
			return
		}
	}

	// Check if it is a valid plugin name
	if _, exists := PluginManager[mode]; exists {
		ScanMode = mode
		LogInfo(GetText("using_single_plugin", mode))
		return
	}

	// Default to All mode
	ScanMode = ModeAll
	LogInfo(GetText("using_default_mode", ModeAll))
	LogInfo(GetText("included_plugins", PluginGroups[ModeAll]))
}

// GetPluginsForMode retrieves the list of plugins for the specified mode
func GetPluginsForMode(mode string) []string {
	plugins, exists := PluginGroups[mode]
	if exists {
		return plugins
	}
	return nil
}

// Helper functions
func IsPortScan() bool    { return ScanMode == ModePort }
func IsICMPScan() bool    { return ScanMode == ModeICMP }
func IsWebScan() bool     { return ScanMode == ModeWeb }
func GetScanMode() string { return ScanMode }

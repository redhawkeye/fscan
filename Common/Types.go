package Common

type HostInfo struct {
	Host    string
	Ports   string
	Url     string
	Infostr []string
}

// ScanPlugin defines the structure of a scan plugin
type ScanPlugin struct {
	Name     string                // Plugin name
	Ports    []int                 // Associated port list, empty slice indicates special scan type
	ScanFunc func(*HostInfo) error // Scan function
}

// HasPort checks if the plugin supports the specified port
func (p *ScanPlugin) HasPort(port int) bool {
	// If no port list is specified, it means all ports are supported
	if len(p.Ports) == 0 {
		return true
	}

	// Check if the port is in the supported list
	for _, supportedPort := range p.Ports {
		if port == supportedPort {
			return true
		}
	}
	return false
}

// PluginManager manages plugin registration
var PluginManager = make(map[string]ScanPlugin)

// RegisterPlugin registers a plugin
func RegisterPlugin(name string, plugin ScanPlugin) {
	PluginManager[name] = plugin
}

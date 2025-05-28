package Common

import (
	"strconv"
	"strings"
	"sort"
)

// ParsePort parses the port configuration string into a list of port numbers
func ParsePort(ports string) []int {
	// Predefined port groups
	portGroups := map[string]string{
		"service": ServicePorts,
		"db":      DbPorts,
		"web":     WebPorts,
		"all":     AllPorts,
		"main":    MainPorts,
	}

	// Check if it matches predefined groups
	if definedPorts, exists := portGroups[ports]; exists {
		ports = definedPorts
	}

	if ports == "" {
		return nil
	}

	var scanPorts []int
	slices := strings.Split(ports, ",")

	// Process each port configuration
	for _, port := range slices {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}

		// Handle port ranges
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				LogError(GetText("port_range_format_error", port))
				continue
			}

			// Ensure the start port is less than the end port
			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}
		}

		// Generate port list
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			if i > 65535 || i < 1 {
				LogError(GetText("ignore_invalid_port", i))
				continue
			}
			scanPorts = append(scanPorts, i)
		}
	}

	// Remove duplicates and sort
	scanPorts = removeDuplicate(scanPorts)
	sort.Ints(scanPorts)

	LogInfo(GetText("valid_port_count", len(scanPorts)))
	return scanPorts
}

// removeDuplicate removes duplicates from an integer slice
func removeDuplicate(old []int) []int {
	temp := make(map[int]struct{})
	var result []int

	for _, item := range old {
		if _, exists := temp[item]; !exists {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

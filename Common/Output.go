package Common

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Global output manager
var ResultOutput *OutputManager

// OutputManager structure for managing output
type OutputManager struct {
	mu            sync.Mutex
	outputPath    string
	outputFormat  string
	file          *os.File
	csvWriter     *csv.Writer
	jsonEncoder   *json.Encoder
	isInitialized bool
}

// ResultType defines the type of result
type ResultType string

const (
	HOST    ResultType = "HOST"    // Host alive
	PORT    ResultType = "PORT"    // Port open
	SERVICE ResultType = "SERVICE" // Service identified
	VULN    ResultType = "VULN"    // Vulnerability found
)

// ScanResult structure for scan results
type ScanResult struct {
	Time    time.Time              `json:"time"`    // Time of discovery
	Type    ResultType             `json:"type"`    // Type of result
	Target  string                 `json:"target"`  // Target (IP/domain/URL)
	Status  string                 `json:"status"`  // Status description
	Details map[string]interface{} `json:"details"` // Detailed information
}

// InitOutput initializes the output system
func InitOutput() error {
	LogDebug(GetText("output_init_start"))

	// Validate output format
	switch OutputFormat {
	case "txt", "json", "csv":
		// Valid formats
	default:
		return fmt.Errorf(GetText("output_format_invalid"), OutputFormat)
	}

	// Validate output path
	if Outputfile == "" {
		return fmt.Errorf(GetText("output_path_empty"))
	}

	dir := filepath.Dir(Outputfile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		LogDebug(GetText("output_create_dir_failed", err))
		return fmt.Errorf(GetText("output_create_dir_failed", err))
	}

	manager := &OutputManager{
		outputPath:   Outputfile,
		outputFormat: OutputFormat,
	}

	if err := manager.initialize(); err != nil {
		LogDebug(GetText("output_init_failed", err))
		return fmt.Errorf(GetText("output_init_failed", err))
	}

	ResultOutput = manager
	LogDebug(GetText("output_init_success"))
	return nil
}

func (om *OutputManager) initialize() error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if om.isInitialized {
		LogDebug(GetText("output_already_init"))
		return nil
	}

	LogDebug(GetText("output_opening_file", om.outputPath))
	file, err := os.OpenFile(om.outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		LogDebug(GetText("output_open_file_failed", err))
		return fmt.Errorf(GetText("output_open_file_failed", err))
	}
	om.file = file

	switch om.outputFormat {
	case "csv":
		LogDebug(GetText("output_init_csv"))
		om.csvWriter = csv.NewWriter(file)
		headers := []string{"Time", "Type", "Target", "Status", "Details"}
		if err := om.csvWriter.Write(headers); err != nil {
			LogDebug(GetText("output_write_csv_header_failed", err))
			file.Close()
			return fmt.Errorf(GetText("output_write_csv_header_failed", err))
		}
		om.csvWriter.Flush()
	case "json":
		LogDebug(GetText("output_init_json"))
		om.jsonEncoder = json.NewEncoder(file)
		om.jsonEncoder.SetIndent("", "  ")
	case "txt":
		LogDebug(GetText("output_init_txt"))
	default:
		LogDebug(GetText("output_format_invalid", om.outputFormat))
	}

	om.isInitialized = true
	LogDebug(GetText("output_init_complete"))
	return nil
}

// SaveResult saves the scan result
func SaveResult(result *ScanResult) error {
	if ResultOutput == nil {
		LogDebug(GetText("output_not_init"))
		return fmt.Errorf(GetText("output_not_init"))
	}

	LogDebug(GetText("output_saving_result", result.Type, result.Target))
	return ResultOutput.saveResult(result)
}

func (om *OutputManager) saveResult(result *ScanResult) error {
	om.mu.Lock()
	defer om.mu.Unlock()

	if !om.isInitialized {
		LogDebug(GetText("output_not_init"))
		return fmt.Errorf(GetText("output_not_init"))
	}

	var err error
	switch om.outputFormat {
	case "txt":
		err = om.writeTxt(result)
	case "json":
		err = om.writeJson(result)
	case "csv":
		err = om.writeCsv(result)
	default:
		LogDebug(GetText("output_format_invalid", om.outputFormat))
		return fmt.Errorf(GetText("output_format_invalid", om.outputFormat))
	}

	if err != nil {
		LogDebug(GetText("output_save_failed", err))
	} else {
		LogDebug(GetText("output_save_success", result.Type, result.Target))
	}
	return err
}

func (om *OutputManager) writeTxt(result *ScanResult) error {
	// Format Details as key-value string
	var details string
	if len(result.Details) > 0 {
		pairs := make([]string, 0, len(result.Details))
		for k, v := range result.Details {
			pairs = append(pairs, fmt.Sprintf("%s=%v", k, v))
		}
		details = strings.Join(pairs, ", ")
	}

	txt := GetText("output_txt_format",
		result.Time.Format("2006-01-02 15:04:05"),
		result.Type,
		result.Target,
		result.Status,
		details,
	) + "\n"
	_, err := om.file.WriteString(txt)
	return err
}

func (om *OutputManager) writeJson(result *ScanResult) error {
	return om.jsonEncoder.Encode(result)
}

func (om *OutputManager) writeCsv(result *ScanResult) error {
	details, err := json.Marshal(result.Details)
	if err != nil {
		details = []byte("{}")
	}

	record := []string{
		result.Time.Format("2006-01-02 15:04:05"),
		string(result.Type),
		result.Target,
		result.Status,
		string(details),
	}

	if err := om.csvWriter.Write(record); err != nil {
		return err
	}
	om.csvWriter.Flush()
	return om.csvWriter.Error()
}

// CloseOutput closes the output system
func CloseOutput() error {
	if ResultOutput == nil {
		LogDebug(GetText("output_no_need_close"))
		return nil
	}

	LogDebug(GetText("output_closing"))
	ResultOutput.mu.Lock()
	defer ResultOutput.mu.Unlock()

	if !ResultOutput.isInitialized {
		LogDebug(GetText("output_no_need_close"))
		return nil
	}

	if ResultOutput.csvWriter != nil {
		LogDebug(GetText("output_flush_csv"))
		ResultOutput.csvWriter.Flush()
	}

	if err := ResultOutput.file.Close(); err != nil {
		LogDebug(GetText("output_close_failed", err))
		return fmt.Errorf(GetText("output_close_failed", err))
	}

	ResultOutput.isInitialized = false
	LogDebug(GetText("output_closed"))
	return nil
}

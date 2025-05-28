package Common

import (
	"fmt"
	"io"
	"log"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Global variable definitions
var (
	// Scan status manager, records the last success and error times
	status = &ScanStatus{lastSuccess: time.Now(), lastError: time.Now()}

	// Num represents the total number of tasks to be processed
	Num int64
	// End represents the number of completed tasks
	End int64
)

// ScanStatus is a struct used to record and manage scan status
type ScanStatus struct {
	mu          sync.RWMutex // Read-write mutex to protect concurrent access
	total       int64        // Total number of tasks
	completed   int64        // Number of completed tasks
	lastSuccess time.Time    // Last success time
	lastError   time.Time    // Last error time
}

// LogEntry defines the structure of a single log entry
type LogEntry struct {
	Level   string    // Log level: ERROR/INFO/SUCCESS/DEBUG
	Time    time.Time // Log time
	Content string    // Log content
}

// Define system-supported log level constants
const (
	LogLevelAll     = "ALL"     // Show all levels of logs
	LogLevelError   = "ERROR"   // Show only error logs
	LogLevelInfo    = "INFO"    // Show only info logs
	LogLevelSuccess = "SUCCESS" // Show only success logs
	LogLevelDebug   = "DEBUG"   // Show only debug logs
)

// Log level to display color mapping
var logColors = map[string]color.Attribute{
	LogLevelError:   color.FgRed,    // Error logs are displayed in red
	LogLevelInfo:    color.FgYellow, // Info logs are displayed in yellow
	LogLevelSuccess: color.FgGreen,  // Success logs are displayed in green
	LogLevelDebug:   color.FgBlue,   // Debug logs are displayed in blue
}

// InitLogger initializes the logging system
func InitLogger() {
	// Disable standard log output
	log.SetOutput(io.Discard)
}

// formatLogMessage formats a log message to a standard format
// Returns format: [time] [level] content
func formatLogMessage(entry *LogEntry) string {
	timeStr := entry.Time.Format("2006-01-02 15:04:05")
	return fmt.Sprintf("[%s] [%s] %s", timeStr, entry.Level, entry.Content)
}

// printLog prints the log based on the log level
func printLog(entry *LogEntry) {
	// Filter logs based on the current log level setting
	shouldPrint := false
	switch LogLevel {
	case LogLevelDebug:
		// DEBUG level shows all logs
		shouldPrint = true
	case LogLevelError:
		// ERROR level shows ERROR, SUCCESS, INFO
		shouldPrint = entry.Level == LogLevelError ||
			entry.Level == LogLevelSuccess ||
			entry.Level == LogLevelInfo
	case LogLevelSuccess:
		// SUCCESS level shows SUCCESS, INFO
		shouldPrint = entry.Level == LogLevelSuccess ||
			entry.Level == LogLevelInfo
	case LogLevelInfo:
		// INFO level shows only INFO
		shouldPrint = entry.Level == LogLevelInfo
	case LogLevelAll:
		// ALL shows all logs
		shouldPrint = true
	default:
		// Default shows only INFO
		shouldPrint = entry.Level == LogLevelInfo
	}

	if !shouldPrint {
		return
	}

	OutputMutex.Lock()
	defer OutputMutex.Unlock()

	// Handle progress bar
	clearAndWaitProgress()

	// Print log message
	logMsg := formatLogMessage(entry)
	if !NoColor {
		// Use colored output
		if colorAttr, ok := logColors[entry.Level]; ok {
			color.New(colorAttr).Println(logMsg)
		} else {
			fmt.Println(logMsg)
		}
	} else {
		// Plain output
		fmt.Println(logMsg)
	}

	// Wait for log output to complete
	time.Sleep(50 * time.Millisecond)

	// Redisplay progress bar
	if ProgressBar != nil {
		ProgressBar.RenderBlank()
	}
}

// clearAndWaitProgress clears the progress bar and waits
func clearAndWaitProgress() {
	if ProgressBar != nil {
		ProgressBar.Clear()
		time.Sleep(10 * time.Millisecond)
	}
}

// LogError records an error log, automatically includes file name and line number information
func LogError(errMsg string) {
	// Get the file name and line number of the caller
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "unknown"
		line = 0
	}
	file = filepath.Base(file)

	errorMsg := fmt.Sprintf("%s:%d - %s", file, line, errMsg)

	entry := &LogEntry{
		Level:   LogLevelError,
		Time:    time.Now(),
		Content: errorMsg,
	}

	handleLog(entry)
}

// handleLog handles the output of logs uniformly
func handleLog(entry *LogEntry) {
	if ProgressBar != nil {
		ProgressBar.Clear()
	}

	printLog(entry)

	if ProgressBar != nil {
		ProgressBar.RenderBlank()
	}
}

// LogInfo records an info log
func LogInfo(msg string) {
	handleLog(&LogEntry{
		Level:   LogLevelInfo,
		Time:    time.Now(),
		Content: msg,
	})
}

// LogSuccess records a success log and updates the last success time
func LogSuccess(result string) {
	entry := &LogEntry{
		Level:   LogLevelSuccess,
		Time:    time.Now(),
		Content: result,
	}

	handleLog(entry)

	// Update the last success time
	status.mu.Lock()
	status.lastSuccess = time.Now()
	status.mu.Unlock()
}

// LogDebug records a debug log
func LogDebug(msg string) {
	handleLog(&LogEntry{
		Level:   LogLevelDebug,
		Time:    time.Now(),
		Content: msg,
	})
}

// CheckErrs checks if the error needs to be retried
func CheckErrs(err error) error {
	if err == nil {
		return nil
	}

	// List of known errors that need to be retried
	errs := []string{
		"closed by the remote host", "too many connections",
		"EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}

	// Check if the error matches
	errLower := strings.ToLower(err.Error())
	for _, key := range errs {
		if strings.Contains(errLower, strings.ToLower(key)) {
			time.Sleep(3 * time.Second)
			return err
		}
	}

	return nil
}

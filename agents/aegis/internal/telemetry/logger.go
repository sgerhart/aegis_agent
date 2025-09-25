package telemetry

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Logger provides basic telemetry logging functionality
type Logger struct {
	logLevel string
	file     *os.File
	mu       sync.RWMutex
}

// LogLevel represents the logging level
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// NewLogger creates a new telemetry logger
func NewLogger(logLevel string) *Logger {
	l := &Logger{
		logLevel: logLevel,
	}
	
	// Try to open log file with fallback options
	logPaths := []string{
		"/var/log/aegis-agent.log",
		"/tmp/aegis-agent.log",
		"./aegis-agent.log",
	}
	
	for _, logPath := range logPaths {
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			l.file = file
			log.Printf("[telemetry] Logging to file: %s", logPath)
			break
		}
	}
	
	if l.file == nil {
		log.Printf("Warning: failed to open any log file, logging to stdout only")
	}
	
	return l
}

// Start starts the telemetry logger
func (l *Logger) Start() {
	log.Printf("[telemetry] Telemetry logger started (level: %s)", l.logLevel)
}

// Stop stops the telemetry logger
func (l *Logger) Stop() {
	if l.file != nil {
		l.file.Close()
	}
	log.Printf("[telemetry] Telemetry logger stopped")
}

// LogInfo logs an info message
func (l *Logger) LogInfo(eventType, message string, metadata map[string]interface{}) {
	l.log(LogLevelInfo, eventType, message, metadata)
}

// LogError logs an error message
func (l *Logger) LogError(eventType, message string, metadata map[string]interface{}) {
	l.log(LogLevelError, eventType, message, metadata)
}

// LogWarn logs a warning message
func (l *Logger) LogWarn(eventType, message string, metadata map[string]interface{}) {
	l.log(LogLevelWarn, eventType, message, metadata)
}

// LogDebug logs a debug message
func (l *Logger) LogDebug(eventType, message string, metadata map[string]interface{}) {
	l.log(LogLevelDebug, eventType, message, metadata)
}

// log logs a message with the specified level
func (l *Logger) log(level LogLevel, eventType, message string, metadata map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	// Check if we should log this level
	if !l.shouldLog(level) {
		return
	}
	
	// Format log entry
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("[%s] [%s] [%s] %s", timestamp, level, eventType, message)
	
	// Add metadata if provided
	if metadata != nil && len(metadata) > 0 {
		logEntry += fmt.Sprintf(" metadata=%v", metadata)
	}
	
	// Write to file if available
	if l.file != nil {
		l.file.WriteString(logEntry + "\n")
		l.file.Sync()
	}
	
	// Also write to stdout for development
	fmt.Println(logEntry)
}

// shouldLog determines if a message should be logged based on the log level
func (l *Logger) shouldLog(level LogLevel) bool {
	switch l.logLevel {
	case "debug":
		return true
	case "info":
		return level == LogLevelInfo || level == LogLevelWarn || level == LogLevelError
	case "warn":
		return level == LogLevelWarn || level == LogLevelError
	case "error":
		return level == LogLevelError
	default:
		return level == LogLevelInfo || level == LogLevelWarn || level == LogLevelError
	}
}

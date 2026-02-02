package masktunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// This file provides small, gopy-friendly helpers for Python bindings.

// ========== Context helpers ==========

var (
	globalCtx    context.Context
	globalCancel context.CancelFunc
	globalOnce   sync.Once
)

// Background returns a process-wide background context.
func Background() context.Context {
	globalOnce.Do(func() {
		globalCtx, globalCancel = context.WithCancel(context.Background())
	})
	return globalCtx
}

// ContextWithCancel wraps a context and its cancel function.
type ContextWithCancel struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewContextWithCancel creates a new cancellable context.
func NewContextWithCancel() *ContextWithCancel {
	ctx, cancel := context.WithCancel(context.Background())
	return &ContextWithCancel{ctx: ctx, cancel: cancel}
}

// Cancel cancels the underlying context.
func (c *ContextWithCancel) Cancel() {
	if c != nil && c.cancel != nil {
		c.cancel()
	}
}

// Context returns the underlying context.
func (c *ContextWithCancel) Context() context.Context {
	if c == nil {
		return context.Background()
	}
	return c.ctx
}

// CancelGlobalContext cancels the global background context.
func CancelGlobalContext() {
	if globalCancel != nil {
		globalCancel()
	}
}

// NewContext returns a new background-derived context.
func NewContext() context.Context {
	return context.Background()
}

// ========== Time constants ==========

var (
	Nanosecond  = time.Nanosecond
	Microsecond = time.Microsecond
	Millisecond = time.Millisecond
	Second      = time.Second
	Minute      = time.Minute
	Hour        = time.Hour
)

// ParseDuration parses a duration string (e.g. "300ms", "2h45m").
func ParseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// ========== Logger bridge ==========

// Zerolog level constants for Python bindings
var (
	LevelTrace = zerolog.TraceLevel
	LevelDebug = zerolog.DebugLevel
	LevelInfo  = zerolog.InfoLevel
	LevelWarn  = zerolog.WarnLevel
	LevelError = zerolog.ErrorLevel
	LevelFatal = zerolog.FatalLevel
	LevelPanic = zerolog.PanicLevel
)

// LogEntry represents a single log entry with metadata
type LogEntry struct {
	LoggerID string
	Message  string
	Time     int64 // Unix timestamp in nanoseconds
}

// Global log buffer for storing log entries
var (
	logBuffer   []LogEntry
	bufferMutex sync.RWMutex
	bufferSize  = 10000 // Maximum number of log entries to keep
	loggerCount int64

	// Channel for notifying new log entries
	logNotifyChannels []chan struct{}
	channelsMutex     sync.RWMutex
)

// addLogEntry adds a log entry to the global buffer
func addLogEntry(loggerID, message string) {
	bufferMutex.Lock()
	defer bufferMutex.Unlock()

	entry := LogEntry{
		LoggerID: loggerID,
		Message:  message,
		Time:     time.Now().UnixNano(),
	}

	// Add to buffer
	logBuffer = append(logBuffer, entry)

	// Keep buffer size under limit (simple FIFO)
	if len(logBuffer) > bufferSize {
		copy(logBuffer, logBuffer[len(logBuffer)-bufferSize:])
		logBuffer = logBuffer[:bufferSize]
	}

	// Notify all waiting listeners
	notifyLogListeners()
}

// notifyLogListeners notifies all registered listeners about new log entries
func notifyLogListeners() {
	channelsMutex.RLock()
	defer channelsMutex.RUnlock()

	for _, ch := range logNotifyChannels {
		select {
		case ch <- struct{}{}:
		default:
			// Channel is full or blocked, skip
		}
	}
}

// GetLogEntries returns and clears log entries from the buffer
func GetLogEntries() []LogEntry {
	bufferMutex.Lock()
	defer bufferMutex.Unlock()

	if len(logBuffer) == 0 {
		return nil
	}

	// Copy and clear buffer
	entries := make([]LogEntry, len(logBuffer))
	copy(entries, logBuffer)
	logBuffer = logBuffer[:0] // Clear buffer but keep capacity

	return entries
}

// WaitForLogEntries waits for new log entries with timeout (in milliseconds)
// Returns log entries when available, or nil on timeout
// If timeoutMs is 0, waits indefinitely
func WaitForLogEntries(timeoutMs int64) []LogEntry {
	// First, check if there are already entries available
	if entries := GetLogEntries(); entries != nil {
		return entries
	}

	// Create a notification channel for this listener
	notifyCh := make(chan struct{}, 1)

	// Register the channel
	channelsMutex.Lock()
	logNotifyChannels = append(logNotifyChannels, notifyCh)
	channelIndex := len(logNotifyChannels) - 1
	channelsMutex.Unlock()

	// Cleanup function to remove the channel
	defer func() {
		channelsMutex.Lock()
		defer channelsMutex.Unlock()
		// Remove the channel from the slice
		if channelIndex < len(logNotifyChannels) {
			logNotifyChannels = append(logNotifyChannels[:channelIndex], logNotifyChannels[channelIndex+1:]...)
		}
	}()

	// Wait for notification or timeout
	if timeoutMs > 0 {
		timer := time.NewTimer(time.Duration(timeoutMs) * time.Millisecond)
		defer timer.Stop()

		select {
		case <-notifyCh:
			return GetLogEntries()
		case <-timer.C:
			return nil // Timeout
		}
	} else {
		// Wait indefinitely
		<-notifyCh
		return GetLogEntries()
	}
}

// CancelLogWaiters cancels all waiting log listeners
func CancelLogWaiters() {
	channelsMutex.Lock()
	defer channelsMutex.Unlock()

	// Close all channels to cancel waiting operations
	for _, ch := range logNotifyChannels {
		close(ch)
	}
	logNotifyChannels = logNotifyChannels[:0] // Clear the slice
}

// NewLoggerWithID creates a new zerolog.Logger that tags output with the given ID
func NewLoggerWithID(id string) zerolog.Logger {
	return zerolog.New(&bufferWriter{id: id}).With().Timestamp().Logger()
}

// NewLoggerWithIDAndLevel creates a new zerolog.Logger with specified level that tags output with the given ID
func NewLoggerWithIDAndLevel(id string, level zerolog.Level) zerolog.Logger {
	return zerolog.New(&bufferWriter{id: id}).Level(level).With().Timestamp().Logger()
}

// NewLogger creates a new zerolog.Logger with auto-generated ID
func NewLogger(cb func(line string)) zerolog.Logger {
	// Generate a unique ID for this logger instance
	loggerCount++
	id := fmt.Sprintf("logger_%d", loggerCount)
	return zerolog.New(&bufferWriter{id: id}).With().Timestamp().Logger()
}

// NewLoggerWithLevel creates a new zerolog.Logger with auto-generated ID and specified level
func NewLoggerWithLevel(level zerolog.Level, cb func(line string)) zerolog.Logger {
	// Generate a unique ID for this logger instance
	loggerCount++
	id := fmt.Sprintf("logger_%d", loggerCount)
	return zerolog.New(&bufferWriter{id: id}).Level(level).With().Timestamp().Logger()
}

// SetLoggerGlobalLevel sets the global log level for all loggers
func SetLoggerGlobalLevel(level zerolog.Level) {
	zerolog.SetGlobalLevel(level)
}

// bufferWriter writes log lines to the global buffer
type bufferWriter struct {
	id string
}

func (w *bufferWriter) Write(p []byte) (int, error) {
	rawLine := strings.TrimSpace(string(p))
	// Only add to buffer if the line is not empty
	if rawLine == "" {
		return len(p), nil
	}
	formattedLine := formatLogLine(rawLine)
	addLogEntry(w.id, formattedLine)
	return len(p), nil
}

// formatLogLine parses a JSON log line and keeps it as JSON for Python to parse
// This avoids double-formatting issues where both Go and Python format the same log
func formatLogLine(line string) string {
	// Try to parse as JSON
	var logObj map[string]interface{}
	if err := json.Unmarshal([]byte(line), &logObj); err != nil {
		// If not valid JSON, wrap it in a simple JSON structure
		simpleLog := map[string]interface{}{
			"level":   "info",
			"message": line,
		}
		if formatted, err := json.Marshal(simpleLog); err == nil {
			return string(formatted)
		}
		return line
	}

	// Extract basic fields
	level, _ := logObj["level"].(string)
	message, _ := logObj["message"].(string)
	if message == "" {
		message, _ = logObj["msg"].(string)
	}

	// Collect extra fields (excluding standard fields) and append to message
	var extraFields []string
	for key, value := range logObj {
		switch key {
		case "level", "time", "message", "msg":
			// Skip standard fields
			continue
		default:
			// Format the field as key=value
			extraFields = append(extraFields, fmt.Sprintf("%s=%v", key, value))
		}
	}

	// Sort extra fields for consistent output
	sort.Strings(extraFields)

	// Build the final message with extra fields
	finalMessage := message
	if len(extraFields) > 0 {
		if finalMessage != "" {
			finalMessage += " " + strings.Join(extraFields, " ")
		} else {
			finalMessage = strings.Join(extraFields, " ")
		}
	}

	// Return a clean JSON structure for Python to parse
	// Don't include timestamp here - let Python add its own
	result := map[string]interface{}{
		"level":   level,
		"message": finalMessage,
	}

	// Convert back to JSON for Python to parse
	if formatted, err := json.Marshal(result); err == nil {
		return string(formatted)
	}

	// Fallback to original line if formatting fails
	return line
}

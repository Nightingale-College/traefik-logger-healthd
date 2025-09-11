package traefik_logger_healthd

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config holds the plugin configuration
type Config struct {
	LogFile        string `json:"logFile,omitempty"`        // Specific log file path (overrides LogDir if set)
	LogDir         string `json:"logDir,omitempty"`         // Directory for rotated logs
	RequestPath    string `json:"requestPath,omitempty"`  // Only log requests matching this path
	RotationFormat string `json:"rotationFormat,omitempty"` // Format for log file rotation (%Y-%m-%d-%H)
	LogFormat      string `json:"logFormat,omitempty"`      // "apache" or "nginx"
	AutoDetect     bool   `json:"autoDetect,omitempty"`     // Auto-detect server type
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		LogFile:        "", // Empty means use LogDir with rotation
		RequestPath:    "/",
		LogDir:         "/var/log/httpd/healthd",      // Default Elastic Beanstalk healthd directory for Apache
		RotationFormat: "application.log.%Y-%m-%d-%H", // Standard Elastic Beanstalk hourly rotation format
		LogFormat:      "apache",                      // Default format (apache or nginx)
		AutoDetect:     true,                          // Automatically detect server type and adjust settings
	}
}

// RequestLogger is the main plugin struct
type RequestLogger struct {
	next           http.Handler
	name           string
	config         *Config
	mutex          sync.Mutex
	logFile        *os.File
	writer         *bufio.Writer
	currentLogPath string
	lastRotation   time.Time
}

// HealthdLogEntry represents a log entry in AWS Elastic Beanstalk healthd format
type HealthdLogEntry struct {
	Timestamp     any    // Unix timestamp in seconds (int64) for Apache, float64 for Nginx
	URI           string // Request URI
	Status        int    // HTTP status code
	RequestTime   any    // Request time in microseconds (int64) for Apache, seconds (float64) for Nginx
	UpstreamTime  any    // Upstream response time (same as RequestTime in our implementation)
	XForwardedFor string // X-Forwarded-For header value
}

// getCurrentLogPath returns the current log file path based on rotation format
func (r *RequestLogger) getCurrentLogPath() string {
	now := time.Now()

	if r.config.LogFile != "" {
		return r.config.LogFile
	}

	// Use time format string to generate the path following AWS Elastic Beanstalk healthd convention
	timeFormat := r.config.RotationFormat

	// Replace AWS Elastic Beanstalk format placeholders (matching rotatelogs format)
	timeFormat = strings.ReplaceAll(timeFormat, "%Y", fmt.Sprintf("%d", now.Year()))
	timeFormat = strings.ReplaceAll(timeFormat, "%m", fmt.Sprintf("%02d", now.Month()))
	timeFormat = strings.ReplaceAll(timeFormat, "%d", fmt.Sprintf("%02d", now.Day()))
	timeFormat = strings.ReplaceAll(timeFormat, "%H", fmt.Sprintf("%02d", now.Hour()))

	return filepath.Join(r.config.LogDir, timeFormat)
}

// ensureLogFileOpen ensures the log file is open and ready for writing
func (r *RequestLogger) ensureLogFileOpen() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	currentPath := r.getCurrentLogPath()

	// If we have a file open already, check if it's the current path
	if r.logFile != nil {
		// If paths match, we're good
		if r.currentLogPath == currentPath {
			return nil
		}

		// Paths don't match, need to close current file
		if r.writer != nil {
			r.writer.Flush()
		}
		r.logFile.Close()
		r.logFile = nil
		r.writer = nil
	}

	// Create parent directory if it doesn't exist
	dir := filepath.Dir(currentPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory for %s: %w", currentPath, err)
	}

	// Open the new log file
	logFile, err := os.OpenFile(currentPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file %s: %w", currentPath, err)
	}

	r.logFile = logFile
	r.writer = bufio.NewWriter(logFile)
	r.currentLogPath = currentPath
	r.lastRotation = time.Now()
	return nil
}

// New creates a new RequestLogger plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Printf("config: %v\n", config)
	// Auto-detect server type if enabled
	if config.AutoDetect {
		// Check for Apache or Nginx environment and adjust defaults if needed
		if _, err := os.Stat("/etc/nginx"); err == nil {
			if config.LogDir == "/var/log/httpd/healthd" {
				// If Nginx is detected and we're using the Apache default, switch to Nginx path
				config.LogDir = "/var/log/nginx/healthd"
			}
			if config.LogFormat == "apache" {
				config.LogFormat = "nginx"
			}
		}
	}

	// Ensure log directory exists if we're not using a specific file path
	if config.LogFile == "" {
		if err := os.MkdirAll(config.LogDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory %s: %w", config.LogDir, err)
		}

		// We'll open the file on first request
		return &RequestLogger{
			next:   next,
			name:   name,
			config: config,
			mutex:  sync.Mutex{},
		}, nil
	}

	// Ensure directory exists for the specific log file path
	dir := filepath.Dir(config.LogFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory for %s: %w", config.LogFile, err)
	}

	// If specific log file is provided, open it now
	logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", config.LogFile, err)
	}

	writer := bufio.NewWriter(logFile)

	return &RequestLogger{
		next:           next,
		name:           name,
		config:         config,
		logFile:        logFile,
		writer:         writer,
		currentLogPath: config.LogFile,
		lastRotation:   time.Now(),
	}, nil
}

// ServeHTTP implements the http.Handler interface
func (r *RequestLogger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	startTime := time.Now()

	// Don't log healthcheck requests if they come from AWS ELB or ALB
	// This is to reduce noise in the logs
	userAgent := req.Header.Get("User-Agent")
	if strings.Contains(userAgent, "ELB-HealthChecker") || strings.Contains(userAgent, "ALB-HealthChecker") {
		return
	}

	fmt.Println("Config", r.config.RequestPath, req.URL.Path)
	if r.config.RequestPath != "" && strings.HasPrefix(r.config.RequestPath, req.URL.Path) {
		// skip request if there is a path filter and it doesn't match
		r.next.ServeHTTP(rw, req)
		return
	}

	// Ensure log file is open and rotated if needed
	if err := r.ensureLogFileOpen(); err != nil {
		// Log to stderr if we can't open the log file
		fmt.Fprintf(os.Stderr, "Error opening healthd log file: %v\n", err)
		// Still process the request but don't attempt to log it
		r.next.ServeHTTP(rw, req)
		return
	}

	// Create a response writer wrapper to capture status code and content size
	wrappedWriter := &responseWriter{
		ResponseWriter: rw,
		statusCode:     0, // Will be set when WriteHeader is called, defaults to 200 in Write() if not set
		contentSize:    0,
	}

	// Get X-Forwarded-For header for logging (if present)
	xForwardedFor := req.Header.Get("X-Forwarded-For")
	if xForwardedFor == "" {
		// Fallback to remote address if X-Forwarded-For is not present
		xForwardedFor = stripPort(req.RemoteAddr)
	}

	// Call the next handler
	r.next.ServeHTTP(wrappedWriter, req)

	// Calculate request time based on format
	duration := time.Since(startTime)

	var timestamp, requestTime, upstreamTime any

	if r.config.LogFormat == "nginx" {
		// Nginx format: timestamp as unix seconds with millisecond precision, request time in seconds
		timestamp = float64(startTime.Unix()) + float64(startTime.Nanosecond())/1e9
		requestTime = float64(duration.Nanoseconds()) / 1e9
		upstreamTime = requestTime // Same as request time in our implementation
	} else {
		// Apache format: timestamp in seconds, request time in microseconds
		timestamp = startTime.Unix()
		requestTime = duration.Microseconds()
		upstreamTime = requestTime // Same as request time in our implementation
	}

	// Create healthd format log entry
	logEntry := HealthdLogEntry{
		Timestamp:     timestamp,
		URI:           req.URL.Path, // Using Path instead of RequestURI to match Apache/Nginx behavior
		Status:        wrappedWriter.statusCode,
		RequestTime:   requestTime,
		UpstreamTime:  upstreamTime, // Same as request time in our implementation
		XForwardedFor: xForwardedFor,
	}

	// Write log entry to file
	r.writeLogEntry(logEntry)
}

// responseWriter wraps http.ResponseWriter to capture status code and content size
type responseWriter struct {
	http.ResponseWriter
	statusCode  int
	contentSize int64
}

// WriteHeader captures the status code
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write ensures status code is set and tracks content size
func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = 200
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.contentSize += int64(n)
	return n, err
}

// writeLogEntry writes a log entry to the file in healthd format
func (r *RequestLogger) writeLogEntry(entry HealthdLogEntry) {
	if r.writer == nil {
		// If writer is not available, we can't log
		return
	}

	r.mutex.Lock()
	defer r.mutex.Unlock()

	var logLine string

	// Format log entry according to AWS Elastic Beanstalk healthd format
	if r.config.LogFormat == "nginx" {
		// Nginx format: $msec"$uri"$status"$request_time"$upstream_response_time"$http_x_forwarded_for
		timestamp, ok := entry.Timestamp.(float64)
		if !ok {
			// Handle type conversion error
			timestamp = float64(time.Now().Unix())
		}

		requestTime, ok := entry.RequestTime.(float64)
		if !ok {
			// Handle type conversion error
			requestTime = 0.0
		}

		upstreamTime, ok := entry.UpstreamTime.(float64)
		if !ok {
			// Handle type conversion error
			upstreamTime = requestTime
		}

		logLine = fmt.Sprintf("%.3f\"%s\"%d\"%.6f\"%.6f\"%s\n",
			timestamp,
			entry.URI,
			entry.Status,
			requestTime,
			upstreamTime,
			entry.XForwardedFor)
	} else {
		// Apache format: %{%s}t"%U"%s"%D"%D"%{X-Forwarded-For}i
		timestamp, ok := entry.Timestamp.(int64)
		if !ok {
			// Handle type conversion error
			timestamp = time.Now().Unix()
		}

		requestTime, ok := entry.RequestTime.(int64)
		if !ok {
			// Handle type conversion error
			requestTime = 0
		}

		upstreamTime, ok := entry.UpstreamTime.(int64)
		if !ok {
			// Handle type conversion error
			upstreamTime = requestTime
		}

		logLine = fmt.Sprintf("%d\"%s\"%d\"%d\"%d\"%s\n",
			timestamp,
			entry.URI,
			entry.Status,
			requestTime,
			upstreamTime,
			entry.XForwardedFor)
	}

	r.writer.WriteString(logLine)

	// Flush the buffer to ensure data is written
	r.writer.Flush()
}

// parseXForwardedFor parses the X-Forwarded-For header and returns a slice of IP addresses
func parseXForwardedFor(xff string) []string {
	var ips []string
	// Split by comma and clean up each IP
	for _, part := range strings.Split(xff, ",") {
		ip := strings.TrimSpace(part)
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

// stripPort removes the port from an IP address string if present
func stripPort(address string) string {
	// Handle IPv6 addresses with ports: [::1]:8080
	if strings.HasPrefix(address, "[") {
		if closeBracket := strings.Index(address, "]"); closeBracket != -1 {
			return address[1:closeBracket]
		}
	}

	// Handle IPv4 addresses with ports: 192.168.1.1:8080
	if host, _, err := net.SplitHostPort(address); err == nil {
		return host
	}

	// Return as-is if no port detected
	return address
}

// extractIPFromForwarded extracts IP from Forwarded header (RFC 7239)
func extractIPFromForwarded(forwarded string) string {
	// Forwarded header format: for=192.0.2.60;proto=http;by=203.0.113.43
	// or: for="[2001:db8:cafe::17]:4711"

	// Simple regex to extract IP from for= parameter
	re := regexp.MustCompile(`for=(?:"?\[?([^\]";,\s]+)\]?:?\d*"?)`)
	matches := re.FindStringSubmatch(forwarded)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

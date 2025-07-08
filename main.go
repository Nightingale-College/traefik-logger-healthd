package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Config holds the plugin configuration
type Config struct {
	LogFile string `json:"logFile,omitempty"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		LogFile: "/var/log/traefik-requests.log",
	}
}

// RequestLogger is the main plugin struct
type RequestLogger struct {
	next    http.Handler
	name    string
	config  *Config
	mutex   sync.Mutex
	logFile *os.File
	writer  *bufio.Writer
}

// HealthdLogEntry represents a log entry in AWS Elastic Beanstalk healthd format
type HealthdLogEntry struct {
	Timestamp    string `json:"timestamp"`
	RequestID    string `json:"request_id"`
	IP           string `json:"ip"`
	Method       string `json:"method"`
	URI          string `json:"uri"`
	Protocol     string `json:"protocol"`
	Status       int    `json:"status"`
	ContentSize  int64  `json:"content_size"`
	RequestTime  int64  `json:"request_time"`
	UserAgent    string `json:"user_agent"`
	Referer      string `json:"referer"`
	XForwardedFor string `json:"x_forwarded_for,omitempty"`
}

// New creates a new RequestLogger plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Open log file for writing (create if doesn't exist, append if exists)
	logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", config.LogFile, err)
	}

	writer := bufio.NewWriter(logFile)

	return &RequestLogger{
		next:    next,
		name:    name,
		config:  config,
		logFile: logFile,
		writer:  writer,
	}, nil
}

// ServeHTTP implements the http.Handler interface
func (r *RequestLogger) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	startTime := time.Now()

	// Generate a unique request ID
	requestID := r.generateRequestID()

	// Create a response writer wrapper to capture status code and content size
	wrappedWriter := &responseWriter{
		ResponseWriter: rw,
		statusCode:     200, // Default status code
		contentSize:    0,
	}

	// Get the client IP address
	clientIP := r.getForwardedIP(req)

	// Get X-Forwarded-For header for logging (if present)
	xForwardedFor := req.Header.Get("X-Forwarded-For")

	// Call the next handler
	r.next.ServeHTTP(wrappedWriter, req)

	// Calculate request time in microseconds (healthd format)
	duration := time.Since(startTime)
	requestTimeUs := duration.Microseconds()

	// Create healthd format log entry
	logEntry := HealthdLogEntry{
		Timestamp:     startTime.Format("2006-01-02T15:04:05.000000Z"),
		RequestID:     requestID,
		IP:            clientIP,
		Method:        req.Method,
		URI:           req.RequestURI,
		Protocol:      req.Proto,
		Status:        wrappedWriter.statusCode,
		ContentSize:   wrappedWriter.contentSize,
		RequestTime:   requestTimeUs,
		UserAgent:     req.Header.Get("User-Agent"),
		Referer:       req.Header.Get("Referer"),
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

// getForwardedIP extracts the most appropriate client IP address from request headers
func (r *RequestLogger) getForwardedIP(req *http.Request) string {
	// First, try to get the real client IP from X-Forwarded-For
	// This is the most reliable for getting the original client IP through proxy chains
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For format: client, proxy1, proxy2
		// We want the leftmost (first) IP which is the original client
		ips := r.parseXForwardedFor(xff)
		if len(ips) > 0 && r.isValidClientIP(ips[0]) {
			return ips[0]
		}
	}

	// Try X-Real-IP (commonly used by nginx)
	if realIP := req.Header.Get("X-Real-IP"); realIP != "" && r.isValidClientIP(realIP) {
		return realIP
	}

	// Try CF-Connecting-IP (Cloudflare's original client IP)
	if cfIP := req.Header.Get("CF-Connecting-IP"); cfIP != "" && r.isValidClientIP(cfIP) {
		return cfIP
	}

	// Try True-Client-IP (used by some CDNs and load balancers)
	if trueIP := req.Header.Get("True-Client-IP"); trueIP != "" && r.isValidClientIP(trueIP) {
		return trueIP
	}

	// Try X-Client-IP (less common but still used)
	if clientIP := req.Header.Get("X-Client-IP"); clientIP != "" && r.isValidClientIP(clientIP) {
		return clientIP
	}

	// Try X-Forwarded (less common variant)
	if forwarded := req.Header.Get("X-Forwarded"); forwarded != "" {
		if ip := r.extractIPFromForwarded(forwarded); ip != "" && r.isValidClientIP(ip) {
			return ip
		}
	}

	// Try standard Forwarded header (RFC 7239)
	if forwarded := req.Header.Get("Forwarded"); forwarded != "" {
		if ip := r.extractIPFromForwarded(forwarded); ip != "" && r.isValidClientIP(ip) {
			return ip
		}
	}

	// Fallback to remote address, strip port if present
	return r.stripPort(req.RemoteAddr)
}

// writeLogEntry writes a log entry to the file in healthd format
func (r *RequestLogger) writeLogEntry(entry HealthdLogEntry) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Convert to JSON
	jsonData, err := json.Marshal(entry)
	if err != nil {
		// If JSON marshaling fails, write a simple log line
		logLine := fmt.Sprintf("ERROR marshaling JSON: timestamp=%s request_id=%s ip=%s method=%s uri=%s status=%d\n",
			entry.Timestamp, entry.RequestID, entry.IP, entry.Method, entry.URI, entry.Status)
		r.writer.WriteString(logLine)
	} else {
		r.writer.Write(jsonData)
		r.writer.WriteString("\n")
	}

	// Flush the buffer to ensure data is written
	r.writer.Flush()
}

// generateRequestID generates a unique request ID similar to healthd format
func (r *RequestLogger) generateRequestID() string {
	// Generate 8 random bytes and encode as hex (16 characters)
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random generation fails
		return fmt.Sprintf("req_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// parseXForwardedFor parses the X-Forwarded-For header and returns a slice of IP addresses
func (r *RequestLogger) parseXForwardedFor(xff string) []string {
	var ips []string
	// Split by comma and clean up each IP
	parts := strings.Split(xff, ",")
	for _, part := range parts {
		ip := strings.TrimSpace(part)
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

// isValidClientIP checks if the IP address is a valid client IP (not private/internal)
func (r *RequestLogger) isValidClientIP(ip string) bool {
	// Remove port if present
	host := r.stripPort(ip)

	// Parse the IP
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return false
	}

	// Reject obviously invalid IPs
	if parsedIP.IsUnspecified() || parsedIP.IsLoopback() {
		return false
	}

	// For IPv4, check for private ranges
	if parsedIP.To4() != nil {
		// Allow private IPs in development/internal environments
		// but prefer public IPs when available
		return true
	}

	// For IPv6, basic validation
	if parsedIP.To16() != nil {
		// Reject IPv6 loopback and link-local addresses
		if parsedIP.Equal(net.IPv6loopback) || parsedIP.IsLinkLocalUnicast() {
			return false
		}
		return true
	}

	return false
}

// isPublicIP checks if an IP address is public (not in private ranges)
func (r *RequestLogger) isPublicIP(ip string) bool {
	host := r.stripPort(ip)
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return false
	}

	// IPv4 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	if parsedIP.To4() != nil {
		return !parsedIP.IsPrivate() && !parsedIP.IsLoopback() && !parsedIP.IsUnspecified()
	}

	// IPv6 - check for private/local ranges
	if parsedIP.To16() != nil {
		return !parsedIP.IsPrivate() && !parsedIP.IsLoopback() && !parsedIP.IsLinkLocalUnicast() && !parsedIP.IsUnspecified()
	}

	return false
}

// stripPort removes the port from an IP address string if present
func (r *RequestLogger) stripPort(address string) string {
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
func (r *RequestLogger) extractIPFromForwarded(forwarded string) string {
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
# Traefik Request Logger Plugin (Healthd Format)

A Traefik plugin that logs detailed request information in AWS Elastic Beanstalk healthd format to a configurable file.

## Features

- Logs in AWS Elastic Beanstalk healthd JSON format
- Generates unique request IDs for tracing
- Captures comprehensive request metadata:
  - Timestamp in ISO 8601 format with microseconds
  - Unique request ID
  - Client IP address (with smart detection)
  - HTTP method, URI, and protocol
  - Response status code and content size
  - Request processing time in microseconds
  - User-Agent and Referer headers
  - X-Forwarded-For header (when present)
- Thread-safe file writing
- Advanced client IP detection through proxy chains

## Configuration

The plugin accepts the following configuration parameter:

- `logFile`: Path to the log file (default: `/var/log/traefik-requests.log`)

## Usage

### Docker Compose Example

```yaml
version: '3.7'

services:
  traefik:
    image: traefik:v3.0
    command:
      - --experimental.plugins.request-logger.modulename=github.com/your-username/traefik-request-logger
      - --experimental.plugins.request-logger.version=v1.0.0
    labels:
      - "traefik.http.middlewares.request-logger.plugin.request-logger.logFile=/var/log/requests.log"
      - "traefik.http.routers.api.middlewares=request-logger"
    volumes:
      - /var/log:/var/log
```

### Static Configuration (traefik.yml)

```yaml
experimental:
  plugins:
    request-logger:
      modulename: github.com/your-username/traefik-request-logger
      version: v1.0.0

http:
  middlewares:
    request-logger:
      plugin:
        request-logger:
          logFile: "/var/log/traefik-requests.log"
```

### Dynamic Configuration

```yaml
http:
  middlewares:
    request-logger:
      plugin:
        request-logger:
          logFile: "/tmp/requests.log"

  routers:
    my-router:
      rule: "Host(`example.com`)"
      middlewares:
        - request-logger
      service: my-service
```

## Log Format (Healthd Compatible)

The plugin outputs JSON logs compatible with AWS Elastic Beanstalk healthd format:

```json
{
  "timestamp": "2024-06-16T10:30:45.123456Z",
  "request_id": "a1b2c3d4e5f6g7h8",
  "ip": "203.0.113.45",
  "method": "GET",
  "uri": "/api/users?page=1&limit=10",
  "protocol": "HTTP/1.1",
  "status": 200,
  "content_size": 1024,
  "request_time": 45000,
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "referer": "https://example.com/dashboard",
  "x_forwarded_for": "203.0.113.45, 198.51.100.1"
}
```

### Field Descriptions

- `timestamp`: ISO 8601 timestamp with microseconds precision
- `request_id`: Unique 16-character hexadecimal request identifier
- `ip`: Most appropriate client IP address (smart detection)
- `method`: HTTP method (GET, POST, etc.)
- `uri`: Complete request URI with query parameters
- `protocol`: HTTP protocol version
- `status`: HTTP response status code
- `content_size`: Response content size in bytes
- `request_time`: Request processing time in microseconds
- `user_agent`: User-Agent header value
- `referer`: Referer header value
- `x_forwarded_for`: X-Forwarded-For header (if present)

## Installation

1. Create a repository with this plugin code
2. Tag a release (e.g., v1.0.0)
3. Configure Traefik to use the plugin as shown in the usage examples above

## Advanced Client IP Detection

The plugin uses sophisticated IP detection logic that checks headers in this priority order:

1. **X-Forwarded-For**: Parses comma-separated IP chains, takes leftmost (original client) IP
2. **X-Real-IP**: Common nginx header for real client IP
3. **CF-Connecting-IP**: Cloudflare's original client IP
4. **True-Client-IP**: Used by some CDNs and load balancers
5. **X-Client-IP**: Alternative client IP header
6. **Forwarded/X-Forwarded**: RFC 7239 standard headers
7. **RemoteAddr**: Final fallback

The plugin validates IPs and handles both IPv4 and IPv6 addresses correctly.

## Development

To test the plugin locally:

1. Clone this repository
2. Run `go mod tidy` to download dependencies
3. Use Traefik's plugin development mode for testing

## Compatibility

- Compatible with AWS Elastic Beanstalk healthd log analysis
- Works with standard log processing tools expecting healthd format
- Integrates with monitoring and alerting systems that parse healthd logs

## License

MIT License
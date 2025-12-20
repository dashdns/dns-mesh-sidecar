# DNS Proxy

A simple DNS proxy server written in Go that forwards DNS queries to an upstream DNS server.

## Features

- Listens on UDP port 53 (configurable)
- Forwards DNS queries to upstream DNS server (default: 1.1.1.1)
- Concurrent request handling using goroutines
- Configurable upstream DNS server
- Verbose logging option
- 5-second timeout for upstream responses

## Installation

```bash
go build -o dns-proxy
```

## Usage

### Basic usage (requires sudo for port 53):

```bash
sudo ./dns-proxy
```

### Run on a different port (no sudo required):

```bash
./dns-proxy -listen :5353
```

### Use a different upstream DNS server:

```bash
sudo ./dns-proxy -upstream 8.8.8.8:53
```

### Enable verbose logging:

```bash
sudo ./dns-proxy -verbose
```

### Combine options:

```bash
./dns-proxy -listen :5353 -upstream 8.8.8.8:53 -verbose
```

## Command-line Flags

- `-listen`: Address to listen on (default: `:53`)
- `-upstream`: Upstream DNS server address (default: `1.1.1.1:53`)
- `-verbose`: Enable verbose logging (default: `false`)
- `-api-port`: API server port (default: `:9090`)

## Testing

You can test the DNS proxy using `dig` or `nslookup`:

### Using dig:

```bash
# If running on port 53
dig @localhost example.com

# If running on port 5353
dig @localhost -p 5353 example.com
```

### Using nslookup:

```bash
# If running on port 53
nslookup example.com localhost

# If running on port 5353
nslookup -port=5353 example.com localhost
```

## API Usage

The DNS proxy includes a REST API server for dynamic blocklist management. The API server runs on port 9090 by default (configurable via `-api-port` flag).

### Update Blocklist

Update the blocklist with a new set of domains to block. This replaces the current blocklist entirely.

**Endpoint:** `POST /api/blocklist`

**Request Body:**
```json
{
  "blocklist": [
    "example.com",
    "ads.example.com",
    "*.tracker.com"
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Blocklist updated successfully",
  "count": 3
}
```

### Examples

#### Basic blocklist update using curl:

```bash
curl -X POST http://localhost:9090/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{
    "blocklist": [
      "ads.example.com",
      "tracker.example.com",
      "malware.com"
    ]
  }'
```

#### Block wildcard domains:

```bash
curl -X POST http://localhost:9090/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{
    "blocklist": [
      "*.doubleclick.net",
      "*.googlesyndication.com",
      "*.facebook.com"
    ]
  }'
```

#### Block multiple ad and tracking domains:

```bash
curl -X POST http://localhost:9090/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{
    "blocklist": [
      "*.googleadservices.com",
      "*.googlesyndication.com",
      "*.doubleclick.net",
      "*.amazon-adsystem.com",
      "*.advertising.com",
      "*.adnxs.com",
      "*.adsrvr.org",
      "analytics.google.com",
      "*.facebook.com",
      "*.twitter.com"
    ]
  }'
```

#### Clear the blocklist (empty list):

```bash
# Note: The API requires at least one entry, so this will return an error
# To effectively clear blocking, send a list with a non-existent domain
curl -X POST http://localhost:9090/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{
    "blocklist": ["_dummy.local"]
  }'
```

#### Load blocklist from a file:

```bash
# Create a blocklist file
cat > blocklist.json <<EOF
{
  "blocklist": [
    "ads.example.com",
    "tracker.example.com",
    "*.analytics.com",
    "*.telemetry.com"
  ]
}
EOF

# Send the file contents to the API
curl -X POST http://localhost:9090/api/blocklist \
  -H "Content-Type: application/json" \
  -d @blocklist.json
```

#### Using with verbose logging:

```bash
# Start the DNS proxy with verbose logging
./dns-proxy -verbose

# In another terminal, update the blocklist
curl -X POST http://localhost:9090/api/blocklist \
  -H "Content-Type: application/json" \
  -d '{
    "blocklist": ["test.example.com"]
  }'

# You'll see detailed logs about the blocklist update in the DNS proxy output
```

### Wildcard Patterns

The blocklist supports wildcard patterns with `*.` prefix:

- `example.com` - Blocks only the exact domain `example.com`
- `*.example.com` - Blocks all subdomains of `example.com` (e.g., `ads.example.com`, `tracker.example.com`)
- Wildcards match any subdomain level (e.g., `*.example.com` matches `a.b.c.example.com`)

### API Response Codes

- `200 OK` - Blocklist updated successfully
- `400 Bad Request` - Invalid JSON or empty blocklist
- `405 Method Not Allowed` - Wrong HTTP method (only POST is supported)

## Notes

- Running on port 53 requires root/administrator privileges
- The proxy handles UDP DNS queries only
- Maximum DNS message size is 512 bytes (standard UDP DNS limit)
- Each query is handled in a separate goroutine for concurrent processing

## Example Output

```
DNS Proxy v0.0.1
Listening on: :53
Upstream DNS: 1.1.1.1:53
Starting DNS proxy...
DNS proxy listening on :53
```

With verbose mode enabled:

```
DNS Proxy v0.0.1
Listening on: :53
Upstream DNS: 1.1.1.1:53
Starting DNS proxy...
DNS proxy listening on :53
2025/12/10 15:30:45 Received 45 bytes from 127.0.0.1:54321
2025/12/10 15:30:45 Processing query from 127.0.0.1:54321
2025/12/10 15:30:45 Forwarded query to 1.1.1.1:53
2025/12/10 15:30:45 Received 61 bytes from upstream
2025/12/10 15:30:45 Sent response to 127.0.0.1:54321
```

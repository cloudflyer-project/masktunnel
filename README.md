# MaskTunnel

🔮 **Advanced HTTP/HTTPS proxy with dynamic browser fingerprinting**

MaskTunnel is a next-generation MITM proxy that combines hazetunnel's User-Agent detection logic with azuretls-client's powerful TLS and HTTP/2 fingerprinting capabilities. It dynamically adapts browser fingerprints based on incoming requests to bypass advanced detection systems.

---

## ✨ Features

### 🎭 Dynamic Browser Fingerprinting
- **TLS Fingerprinting**: Emulate ClientHello of browsers based on User-Agent (Chrome, Firefox, Safari, Edge)
- **HTTP/2 Fingerprinting**: Dynamic SETTINGS, WINDOW_UPDATE, and PRIORITY frames matching real browsers
- **Auto-Detection**: Automatically detects browser type and version from User-Agent headers

### 💉 JavaScript Payload Injection
- Prepends custom JavaScript to all JavaScript responses
- Injects payloads into base64 encoded JavaScript within HTML responses
- Supports both inline and external script modification

### 🔒 Advanced Proxy Features
- HTTP Basic authentication support
- Upstream proxy chaining
- HTTPS tunneling via CONNECT method
- Request/response logging and debugging

### 🌍 Browser Support
- **Chrome** (58, 62, 70, 72, 83, 87, 96, 100, 102, 106, 112, 114, 115, 120, 131, 133)
- **Firefox** (55, 56, 63, 65, 99, 102, 105, 120)
- **Safari** (16.0)
- **Edge** (85)
- **iOS** (11, 12, 13, 14)

---

## 🚀 Quick Start

### Building from Source

```bash
git clone <repository-url>
cd masktunnel
go build ./cmd/masktunnel
```

### Basic Usage

Start a basic proxy:
```bash
./masktunnel -port 8080
```

With payload injection:
```bash
./masktunnel -payload "console.log('MaskTunnel injected!');" -port 8080
```

With authentication:
```bash
./masktunnel -username myuser -password mypass -port 8080
```

With upstream proxy:
```bash
./masktunnel -upstream-proxy http://upstream:8080 -port 8080
```

### Usage Examples

#### Test with Chrome User-Agent
```bash
curl -x http://localhost:8080 \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
     https://tls.peet.ws/api/all
```

Expected HTTP/2 fingerprint:
```json
{
  "akamai_fingerprint": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,s,a,p"
}
```

#### Test with Firefox User-Agent
```bash
curl -x http://localhost:8080 \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0" \
     https://tls.peet.ws/api/all
```

Expected HTTP/2 fingerprint:
```json
{
  "akamai_fingerprint": "1:65536;2:0;4:131072;5:16384|12517377|0|m,s,a,p"
}
```

---

## 📋 Command Line Options

```
Usage of masktunnel:
  -addr string
        Proxy listen address
  -cert string
        TLS CA certificate (generated automatically if not present) (default "cert.pem")
  -key string
        TLS CA key (generated automatically if not present) (default "key.pem")
  -password string
        Password for proxy authentication. Optional.
  -payload string
        Payload to inject into responses. Optional.
  -port string
        Proxy listen port (default "8080")
  -upstream-proxy string
        Forward requests to an upstream proxy. Optional.
  -user-agent string
        Override the User-Agent header for incoming requests. Optional.
  -username string
        Username for proxy authentication. Optional.
  -verbose
        Enable verbose logging
```

---

## 🏗️ Architecture

MaskTunnel consists of several key components:

### 📦 Modules

- **`fingerprint`**: User-Agent parsing and browser fingerprint generation
- **`session`**: azuretls-client session management with browser-specific configurations
- **`injector`**: JavaScript payload injection into responses
- **`auth`**: HTTP Basic authentication for proxy access
- **`proxy`**: Core HTTP/HTTPS proxy server implementation

### 🔄 Request Flow

1. **Authentication**: Validate proxy credentials (if enabled)
2. **UA Detection**: Parse User-Agent to determine browser type and version
3. **Session Creation**: Get or create azuretls session with appropriate fingerprints
4. **Request Forwarding**: Send request using azuretls-client with correct TLS/HTTP2 fingerprint
5. **Response Processing**: Inject JavaScript payload (if applicable)
6. **Response Delivery**: Return modified response to client

---

## 🎯 Browser Fingerprint Details

### Chrome 120+ Fingerprint
- **TLS**: Latest Chrome ClientHello with GREASE, PQ key exchange
- **HTTP/2**: `1:65536,2:0,4:6291456,6:262144|15663105|0|m,s,a,p`
- **Headers**: Chrome-style header ordering and values

### Firefox 120+ Fingerprint
- **TLS**: Firefox-specific cipher suites and extensions
- **HTTP/2**: `1:65536,2:0,4:131072,5:16384|12517377|0|m,s,a,p`
- **Headers**: Firefox-style header ordering

### Safari 16+ Fingerprint
- **TLS**: Safari/WebKit ClientHello patterns
- **HTTP/2**: `2:0,3:100,4:2097152,8:1,9:1|10420225|0|m,s,a,p`
- **Headers**: Safari-specific header patterns

---

## 🔧 Configuration

### Environment Variables

MaskTunnel can be configured via environment variables:

```bash
export MASKTUNNEL_PORT=8080
export MASKTUNNEL_VERBOSE=true
export MASKTUNNEL_PAYLOAD="console.log('injected');"
```

### Payload Injection Examples

Simple console logging:
```bash
./masktunnel -payload "console.log('MaskTunnel active');"
```

Advanced fingerprint defense:
```bash
./masktunnel -payload "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
```

---

## 🤝 Differences from Hazetunnel

| Feature | Hazetunnel | MaskTunnel |
|---------|------------|------------|
| **Architecture** | goproxy + utls | Pure azuretls-client |
| **HTTP/2 Fingerprint** | Fixed Go default | Dynamic per browser |
| **TLS Fingerprint** | utls only | azuretls enhanced |
| **Code Complexity** | Mixed architecture | Clean, focused design |
| **Performance** | Good | Better (single stack) |
| **Maintainability** | Multiple dependencies | Unified dependency |

---

## 🙏 Acknowledgments

MaskTunnel builds upon the excellent work of:
- [hazetunnel](https://github.com/daijro/hazetunnel) - User-Agent detection and payload injection logic
- [azuretls-client](https://github.com/Noooste/azuretls-client) - Advanced TLS and HTTP/2 fingerprinting
- [tlsproxy](https://github.com/rosahaj/tlsproxy) - Original proxy foundation

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

*Ready to mask your traffic with precision? 🎭*

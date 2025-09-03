# MaskTunnel

A smart proxy that automatically mimics different browsers to bypass detection systems.

## What is MaskTunnel?

MaskTunnel is an HTTP proxy that automatically changes its "fingerprint" to match different browsers (Chrome, Firefox, Safari, etc.) based on the User-Agent header in requests. This helps bypass websites that try to detect and block automated traffic.

**Key benefits:**
- **JA3/JA4 TLS fingerprint simulation**: Mimics real browser JA3/JA4 TLS fingerprints (Chrome, Firefox, Safari, Edge)
- **Akamai HTTP/2 fingerprint bypass**: Replicates browser-specific HTTP/2 SETTINGS and frame patterns
- **Dynamic adaptation**: Automatically selects correct fingerprints based on User-Agent headers
- **JavaScript injection**: Inject custom code to bypass client-side detection
- **Zero configuration**: Works out-of-the-box with any HTTP client or browser

## Installation

### Docker (Recommended)

```bash
# Run with default settings
docker run -p 8080:8080 jackzzs/masktunnel
```

### Binary Releases

Download pre-built binaries from the [releases page](../../releases).

### Build from Source

```bash
git clone https://github.com/cloudflyer-project/masktunnel
cd masktunnel
go build ./cmd/masktunnel
```

## Usage

### Start the Proxy

Basic proxy on port 8080:
```bash
./masktunnel -port 8080
```

Configure your browser or application to use `http://localhost:8080` as the HTTP proxy.

### Common Options

Add authentication:
```bash
./masktunnel -username myuser -password mypass -port 8080
```

Inject custom JavaScript into web pages:
```bash
./masktunnel -payload "console.log('Hello from MaskTunnel!');" -port 8080
```

Chain through another proxy:
```bash
./masktunnel -upstream-proxy http://upstream:8080 -port 8080
```

### Testing the Fingerprinting

Test that different User-Agents produce different fingerprints:

**Chrome fingerprint:**
```bash
curl -x http://localhost:8080 \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
     https://tls.peet.ws/api/all
```

**Firefox fingerprint:**
```bash
curl -x http://localhost:8080 \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0" \
     https://tls.peet.ws/api/all
```

The fingerprints returned should be different for each browser.

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-port` | Proxy listen port | `8080` |
| `-addr` | Proxy listen address | `` |
| `-username` | Username for proxy authentication | `` |
| `-password` | Password for proxy authentication | `` |
| `-payload` | JavaScript to inject into responses | `` |
| `-upstream-proxy` | Forward requests to upstream proxy | `` |
| `-user-agent` | Override User-Agent header | `` |
| `-cert` | TLS certificate file | `cert.pem` |
| `-key` | TLS key file | `key.pem` |
| `-verbose` | Enable verbose logging | `false` |

## Acknowledgments

MaskTunnel builds upon the excellent work of:
- [hazetunnel](https://github.com/daijro/hazetunnel) - User-Agent detection and payload injection logic
- [azuretls-client](https://github.com/Noooste/azuretls-client) - Advanced TLS and HTTP/2 fingerprinting

## License

This project is licensed under the GPLv3 License.

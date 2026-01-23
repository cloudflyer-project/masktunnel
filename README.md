[![GitHub Stars](https://img.shields.io/github/stars/cloudflyer-project/masktunnel?style=flat&logo=github)](https://github.com/cloudflyer-project/masktunnel) [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/cloudflyer-project/masktunnel/test.yml?logo=github&label=Tests)](https://github.com/cloudflyer-project/masktunnel/actions) ![Python Version](https://img.shields.io/badge/python_version-%3E%203.9-blue?logo=python&logoColor=white) [![PyPI - Version](https://img.shields.io/pypi/v/masktunnel?logo=pypi&logoColor=white)](https://pypi.org/project/masktunnel/) ![Go Version](https://img.shields.io/github/go-mod/go-version/cloudflyer-project/masktunnel) ![License](https://img.shields.io/github/license/cloudflyer-project/masktunnel)

# MaskTunnel

A smart proxy that automatically mimics different browsers to bypass detection systems.

[中文文档 / Chinese README](README_zh.md)

## What is MaskTunnel?

MaskTunnel is an HTTP proxy that automatically changes its "fingerprint" to match different browsers (Chrome, Firefox, Safari, etc.) based on the User-Agent header in requests. This helps bypass websites that try to detect and block automated traffic.

**Key benefits:**
- **JA3/JA4 TLS fingerprint simulation**: Mimics real browser JA3/JA4 TLS fingerprints (Chrome, Firefox, Safari, Edge)
- **Akamai HTTP/2 fingerprint bypass**: Replicates browser-specific HTTP/2 SETTINGS and frame patterns
- **Dynamic adaptation**: Automatically selects correct fingerprints based on User-Agent headers
- **JavaScript injection**: Inject custom code to bypass client-side detection
- **Zero configuration**: Works out-of-the-box with any HTTP client or browser
- **Supports streaming**: Support chunked and websocket connections

## Installation

### Docker (Recommended)

```bash
# Run with default settings
docker run -p 8080:8080 jackzzs/masktunnel
```

### Binary Releases

Download pre-built binaries from the [releases page](https://github.com/cloudflyer-project/masktunnel/releases).

### Python Version

```bash
pip install masktunnel
```

> The Python version is a wrapper of the Go implementation. See [Python Bindings](#python-bindings) for usage.

### Build from Source

```bash
go run github.com/cloudflyer-project/masktunnel/cmd/masktunnel
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
curl -k -x http://localhost:8080 \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
     https://tls.peet.ws/api/all
```

**Firefox fingerprint:**
```bash
curl -k -x http://localhost:8080 \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0" \
     https://tls.peet.ws/api/all
```

The fingerprints returned should be different for each browser.

> **Note:** The `-k` flag disables SSL certificate verification. For production use, see [Trusting the Certificate](#trusting-the-certificate) below.

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-port` | Proxy listen port | `8080` |
| `-addr` | Proxy listen address | |
| `-username` | Username for proxy authentication | |
| `-password` | Password for proxy authentication | |
| `-payload` | JavaScript to inject into responses | |
| `-upstream-proxy` | Forward requests to upstream proxy | |
| `-user-agent` | Override User-Agent header | |
| `-cert` | TLS certificate file | `cert.pem` |
| `-key` | TLS key file | `key.pem` |
| `-verbose` | Enable verbose logging | `0` |

## Trusting the Certificate

MaskTunnel acts as a MITM (Man-in-the-Middle) proxy to intercept and modify HTTPS traffic. By default, it generates a self-signed certificate that browsers and tools will not trust, requiring the `-k` flag in curl or similar options in other clients.

To avoid certificate warnings and use MaskTunnel without `-k`, you can add the generated certificate to your system's trusted certificate store.

### Certificate Location

The certificate file is located at:
- Default: `cert.pem` in the working directory
- Custom: Specified via `-cert` flag

### Windows

1. Double-click the `cert.pem` file, or rename it to `cert.crt` and double-click
2. Click **Install Certificate...**
3. Select **Local Machine** (requires admin) or **Current User**
4. Choose **Place all certificates in the following store**
5. Click **Browse** and select **Trusted Root Certification Authorities**
6. Click **Next** and then **Finish**

Alternatively, using PowerShell (as Administrator):
```powershell
Import-Certificate -FilePath "cert.pem" -CertStoreLocation Cert:\LocalMachine\Root
```

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert.pem
```

Or via Keychain Access:
1. Open **Keychain Access** (Applications → Utilities)
2. Drag `cert.pem` into the **System** keychain
3. Double-click the imported certificate
4. Expand **Trust** and set **When using this certificate** to **Always Trust**
5. Close the window and enter your password to confirm

### Linux

**Debian/Ubuntu:**
```bash
sudo cp cert.pem /usr/local/share/ca-certificates/masktunnel.crt
sudo update-ca-certificates
```

**RHEL/CentOS/Fedora:**
```bash
sudo cp cert.pem /etc/pki/ca-trust/source/anchors/masktunnel.pem
sudo update-ca-trust
```

**Arch Linux:**
```bash
sudo cp cert.pem /etc/ca-certificates/trust-source/anchors/masktunnel.crt
sudo trust extract-compat
```

### Browser-Specific Trust

Some browsers maintain their own certificate stores:

**Firefox:** Go to Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import

**Chrome (Linux):** Chrome uses the system store on most platforms, but on Linux you may need:
```bash
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "MaskTunnel" -i cert.pem
```

## Acknowledgments

MaskTunnel builds upon the excellent work of:
- [hazetunnel](https://github.com/daijro/hazetunnel) - User-Agent detection and payload injection logic
- [azuretls-client](https://github.com/Noooste/azuretls-client) - Advanced TLS and HTTP/2 fingerprinting

## License

This project is licensed under the GPLv3 License.

# MaskTunnel Python Bindings

[![PyPI version](https://img.shields.io/pypi/v/masktunnel.svg)](https://pypi.org/project/masktunnel/)
[![Python versions](https://img.shields.io/pypi/pyversions/masktunnel.svg)](https://pypi.org/project/masktunnel/)

Python bindings for MaskTunnel — an HTTP(S) MITM proxy that adapts its browser fingerprint based on the request User-Agent.

This package wraps the Go implementation and exposes a Python-friendly API.

## Overview

MaskTunnel is an HTTP proxy that dynamically changes its fingerprint to mimic real browsers (Chrome / Firefox / Safari / Edge) according to the User-Agent header in requests.

Key capabilities:

- Browser-like TLS fingerprints (JA3 / JA4)
- Browser-like HTTP/2 fingerprints (e.g. Akamai-style settings and frame patterns)
- Automatic selection based on User-Agent
- Optional response JavaScript injection
- Optional upstream proxy chaining

## Installation

### Using pip (Recommended)

```bash
pip install masktunnel
```

### Build from source (sdist)

Building from source requires:

- Python 3.9+
- Go toolchain
- A C toolchain suitable for building Python extensions

## Quick Start

### Run a proxy server

```python
from masktunnel import Server

server = Server()
print(f"Proxy running at: {server.addr}")

# Blocking; run in a thread if needed
server.start()
```

### Use CLI

After installation:

```bash
masktunnel server --port 8080
```

## API

### `Server`

Create a server with options:

```python
from masktunnel import Server
from masktunnel._server import ServerOptions

opts = ServerOptions(
	port="8080",
	username="",
	password="",
	payload="",
	upstream_proxy="",
	user_agent="",
	verbose=0,
)

server = Server(options=opts)
```

Common operations:

```python
server.start()
server.stop()
server.reset_sessions()
```

## Notes

- The native module is generated at build time into `masktunnellib/`.
- Prefer installing wheels when available; building from source depends on the local toolchain.

## Links

- Source: https://github.com/cloudflyer-project/masktunnel

# vless-client

A lightweight CLI proxy client built on [xray-core](https://github.com/xtls/xray-core). It parses a VLESS link or a WireGuard config and exposes a local SOCKS5 and/or HTTP proxy — no manual JSON config required.

Created as a companion tool for [WireTurn](https://github.com/spkprsnts/WireTurn).

## Features

- **VLESS** proxy from a `vless://` link — supports TLS, REALITY, WebSocket, gRPC, TCP, XHTTP
- **WireGuard** tunnel — from a standard `.conf` file or individual CLI flags
- **Standalone SOCKS5** upstream proxy mode
- **Dual-route** mode with automatic failover and load balancing
- SOCKS5 proxy (always on)
- Optional HTTP proxy on a separate port
- Optional username/password auth on exposed SOCKS5 and HTTP proxies
- Authenticated upstream SOCKS5 (`user:pass@host:port`)
- Configurable DNS servers
- HTTP metrics endpoint (`/metrics`) in wireproxy-compatible format
- Health check endpoints (`/status`, `/check`) for monitoring
- Debug logging via flag

## Installation

**Requirements:** Go 1.22+

```bash
git clone https://github.com/spkprsnts/vless-client
cd vless-client
go build -o vless-client .
```

## Usage

### VLESS — single route

```bash
./vless-client -link "vless://UUID@host:port?security=reality&..." -listen 127.0.0.1:1080
```

With a local/CDN address override:

```bash
./vless-client \
  -link          "vless://UUID@host:port?security=reality&..." \
  -local-address 192.168.1.1:443 \
  -listen        127.0.0.1:1080
```

### VLESS — dual route with load balancer

Connects through both a local/CDN address and the direct server address. Automatically uses whichever is reachable (lowest RTT).

```bash
./vless-client \
  -link           "vless://UUID@host:port?security=reality&..." \
  -local-address  192.168.1.1:443 \
  -direct-address server.example.com:443 \
  -listen         127.0.0.1:1080 \
  -metrics        127.0.0.1:8080
```

### VLESS — dual route with local SOCKS5 upstream

Connects through a local SOCKS5 proxy and the direct VLESS server. Automatically uses whichever is reachable.

```bash
./vless-client \
  -link           "vless://UUID@host:port?security=reality&..." \
  -local-socks5   127.0.0.1:1081 \
  -direct-address server.example.com:443 \
  -listen         127.0.0.1:1080 \
  -metrics        127.0.0.1:8080
```

### Standalone SOCKS5 upstream

Use an existing SOCKS5 proxy as the upstream without any tunnel:

```bash
./vless-client \
  -local-socks5 127.0.0.1:1081 \
  -listen       127.0.0.1:1080
```

### WireGuard — from a config file

```bash
./vless-client -wg /etc/wireguard/wg0.conf -listen 127.0.0.1:1080
```

### WireGuard — from flags

```bash
./vless-client \
  -wg-private-key <base64-private-key> \
  -wg-public-key  <base64-public-key> \
  -wg-endpoint    vpn.example.com:51820 \
  -wg-address     10.0.0.2/32 \
  -listen         127.0.0.1:1080
```

### Authentication

Protect the exposed proxy with a username and password:

```bash
./vless-client \
  -link       "vless://UUID@host:port?security=reality&..." \
  -listen     127.0.0.1:1080 \
  -proxy-user alice \
  -proxy-pass secret
```

Both SOCKS5 and HTTP (`-http`) inbounds use the same credentials. Works with any mode (VLESS, WireGuard, standalone SOCKS5).

Connect through an upstream SOCKS5 that requires auth:

```bash
./vless-client \
  -local-socks5 alice:secret@127.0.0.1:1081 \
  -listen       127.0.0.1:1080
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `-listen` | *(required)* | SOCKS5 proxy listen address `ip:port` |
| `-link` | | VLESS link (`vless://...`) |
| `-local-address` | | Override destination `host:port` for VLESS (local/CDN route) |
| `-direct-address` | | Direct server `host:port`; enables load balancing between local and direct routes |
| `-local-socks5` | | Local SOCKS5 proxy `[user:pass@]host:port`. Used as standalone upstream, or as the local route when `-link` and `-direct-address` are also set |
| `-wg` | | Path to WireGuard `.conf` file |
| `-wg-private-key` | | WireGuard private key |
| `-wg-public-key` | | WireGuard peer public key |
| `-wg-preshared-key` | | WireGuard preshared key (optional) |
| `-wg-endpoint` | | WireGuard peer endpoint `host:port` |
| `-wg-address` | | WireGuard interface addresses, comma-separated |
| `-wg-mtu` | | WireGuard MTU (optional) |
| `-wg-keepalive` | | Persistent keepalive in seconds (optional) |
| `-http` | | Optional HTTP proxy address `ip:port` |
| `-dns` | `8.8.8.8,1.1.1.1` | Comma-separated DNS servers |
| `-metrics` | | HTTP metrics/status endpoint address `ip:port` |
| `-hc-interval` | `30` | Health check interval in seconds (dual-route mode) |
| `-proxy-user` | | Username for the exposed SOCKS5/HTTP proxy |
| `-proxy-pass` | | Password for the exposed SOCKS5/HTTP proxy |
| `-debug` | `false` | Enable xray-core debug logging |

> **WireGuard config priority:** individual `-wg-*` flags override values from `-wg` config file.

## Metrics & status

When `-metrics` is set, a lightweight HTTP server exposes three endpoints.

### `/metrics` — traffic counters (wireproxy-compatible format)

```
tx_bytes=123456
rx_bytes=654321
```

### `/status` — outbound health (JSON, dual-route mode only)

```json
{
  "outbounds": [
    {
      "tag": "local",
      "alive": true,
      "ping": {
        "avg_ms": 45,
        "min_ms": 42,
        "max_ms": 50,
        "total": 10,
        "fail": 0
      }
    },
    {
      "tag": "direct",
      "alive": false,
      "ping": {
        "avg_ms": 0,
        "min_ms": 0,
        "max_ms": 0,
        "total": 10,
        "fail": 10
      }
    }
  ],
  "active": "local"
}
```

`active` is the tag of the currently selected outbound (lowest RTT among alive), or `"none"` if both are unreachable. The first check runs at startup and takes up to 5 seconds.

### `/check` — trigger manual health checks (dual-route mode only)

Triggers `n` rounds of health checks for both routes (default 1, max 10).

```
GET /check?n=3
```

Response:
```json
{"status":"check started","rounds":3}
```

## License

MIT

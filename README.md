# vless-client

A lightweight CLI proxy client built on [xray-core](https://github.com/xtls/xray-core). It parses a VLESS link or a WireGuard config and exposes a local SOCKS5 and/or HTTP proxy — no manual JSON config required.

Created as a companion tool for [WireTurn](https://github.com/spkprsnts/WireTurn).

## Features

- **VLESS** proxy from a `vless://` link — supports TLS, REALITY, WebSocket, gRPC, TCP
- **WireGuard** tunnel — from a standard `.conf` file or individual CLI flags
- **Standalone SOCKS5** upstream proxy mode
- **Dual-route** mode with automatic failover and load balancing
- SOCKS5 proxy (always on)
- Optional HTTP proxy on a separate port
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

### VLESS mode — single route

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

### VLESS mode — dual route with load balancer

Connects through both a local/CDN address and the direct server address. Automatically uses whichever is reachable.

```bash
./vless-client \
  -link           "vless://UUID@host:port?security=reality&..." \
  -local-address  192.168.1.1:443 \
  -direct-address server.example.com:443 \
  -listen         127.0.0.1:1080 \
  -metrics        127.0.0.1:8080
```

### WireGuard mode — from a config file

```bash
./vless-client -wg /etc/wireguard/wg0.conf -listen 127.0.0.1:1080
```

### WireGuard mode — from flags

```bash
./vless-client \
  -wg-private-key <base64-private-key> \
  -wg-public-key  <base64-public-key> \
  -wg-endpoint    vpn.example.com:51820 \
  -wg-address     10.0.0.2/32 \
  -listen         127.0.0.1:1080
```

## Usage (continued)

### Standalone SOCKS5 upstream mode

Use an existing SOCKS5 proxy as the upstream:

```bash
./vless-client \
  -local-socks5   127.0.0.1:1081 \
  -listen         127.0.0.1:1080
```

### VLESS mode — dual route with local SOCKS5 upstream

Connects through a local SOCKS5 proxy and the direct VLESS server. Automatically uses whichever is reachable.

```bash
./vless-client   -link           "vless://UUID@host:port?security=reality&..."   -local-socks5   127.0.0.1:1081   -direct-address server.example.com:443   -listen         127.0.0.1:1080   -metrics        127.0.0.1:8080
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `-listen` | *(required)* | SOCKS5 proxy listen address `ip:port` |
| `-link` | | VLESS link (`vless://...`) |
| `-local-address` | | Override destination `host:port` for VLESS (local/CDN route) |
| `-direct-address` | | Direct server `host:port`; enables load balancing between local and direct routes |
| `-local-socks5` | | Local SOCKS5 proxy `host:port`. Used as standalone upstream, or instead of local VLESS if -link and -direct-address are set |
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
| `-debug` | `false` | Enable xray-core debug logging |

> **Priority (WireGuard):** individual `wg-*` flags > `-wg` config file > `-link` VLESS.

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

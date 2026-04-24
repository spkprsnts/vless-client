package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"

	// Blank imports for xray-core features.
	// These are required to register the components with the core.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/stats"
	_ "github.com/xtls/xray-core/proxy/http"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
	_ "github.com/xtls/xray-core/proxy/wireguard"

	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/router"
)

type VLessConfig struct {
	UUID    string
	Address string
	Port    int
	Params  map[string]string
}

// WireGuard config structs
type WireGuardInterfaceConfig struct {
	PrivateKey string
	Address    []string
	MTU        int
}

type WireGuardPeerConfig struct {
	PublicKey    string
	PresharedKey string
	Endpoint     string
	KeepAlive    int
}

// Simple INI parser for WireGuard config
func parseWireGuardConfig(path string) (*WireGuardInterfaceConfig, *WireGuardPeerConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	iface := &WireGuardInterfaceConfig{}
	peer := &WireGuardPeerConfig{}
	inInterfaceSection := false
	inPeerSection := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.EqualFold(line, "[Interface]") {
			inInterfaceSection = true
			inPeerSection = false
			continue
		}

		if strings.EqualFold(line, "[Peer]") {
			inPeerSection = true
			inInterfaceSection = false
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		if inInterfaceSection {
			switch strings.ToLower(key) {
			case "privatekey":
				iface.PrivateKey = value
			case "address":
				for addr := range strings.SplitSeq(value, ",") {
					iface.Address = append(iface.Address, strings.TrimSpace(addr))
				}
			case "mtu":
				iface.MTU, _ = strconv.Atoi(value)
			}
		} else if inPeerSection {
			switch strings.ToLower(key) {
			case "publickey":
				peer.PublicKey = value
			case "presharedkey":
				peer.PresharedKey = value
			case "endpoint":
				peer.Endpoint = value
			case "persistentkeepalive":
				peer.KeepAlive, _ = strconv.Atoi(value)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	if iface.PrivateKey == "" || peer.PublicKey == "" || peer.Endpoint == "" {
		return nil, nil, fmt.Errorf("invalid wireguard config: missing PrivateKey, PublicKey, or Endpoint")
	}

	return iface, peer, nil
}

// Generate Xray configuration for WireGuard
func buildWireGuardXrayConfig(iface *WireGuardInterfaceConfig, peer *WireGuardPeerConfig, listenAddr, httpAddr string, dns []string, debug bool) ([]byte, error) {
	logLevel := "error"
	logAccess := "none"
	if debug {
		logLevel = "debug"
		logAccess = ""
	}

	// Inbounds
	var inbounds []any
	listenHost, listenPortStr, _ := net.SplitHostPort(listenAddr)
	listenPort, _ := strconv.Atoi(listenPortStr)

	inbounds = append(inbounds, map[string]any{
		"listen":   listenHost,
		"port":     listenPort,
		"protocol": "socks",
		"settings": map[string]any{"udp": true},
		"sniffing": map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		},
	})

	if httpAddr != "" {
		httpHost, httpPortStr, _ := net.SplitHostPort(httpAddr)
		httpPort, _ := strconv.Atoi(httpPortStr)
		inbounds = append(inbounds, map[string]any{
			"listen":   httpHost,
			"port":     httpPort,
			"protocol": "http",
			"settings": map[string]any{"timeout": 0},
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": []string{"http", "tls"},
			},
		})
	}

	peerConfig := map[string]any{
		"publicKey": peer.PublicKey,
		"endpoint":  peer.Endpoint,
	}
	if peer.PresharedKey != "" {
		peerConfig["preSharedKey"] = peer.PresharedKey
	}
	if peer.KeepAlive > 0 {
		peerConfig["keepAlive"] = peer.KeepAlive
	}

	wgSettings := map[string]any{
		"secretKey": iface.PrivateKey,
		"address":   iface.Address,
		"peers":     []any{peerConfig},
	}
	if iface.MTU > 0 {
		wgSettings["mtu"] = iface.MTU
	}

	// Full configuration
	configJSON := map[string]any{
		"log":   map[string]any{"loglevel": logLevel, "access": logAccess},
		"stats": map[string]any{},
		"dns": map[string]any{
			"servers": dns,
		},
		"policy": map[string]any{
			"system": map[string]any{
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{
				"tag":      "proxy",
				"protocol": "wireguard",
				"settings": wgSettings,
			},
		},
	}
	return json.MarshalIndent(configJSON, "", "  ")
}

// Parse VLESS link
func parseVLessLink(link string) (*VLessConfig, error) {
	link = strings.TrimPrefix(link, "vless://")
	parts := strings.SplitN(link, "@", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid vless link: missing '@'")
	}
	uuid := parts[0]
	remaining := parts[1]

	hostPortAndParams := strings.SplitN(remaining, "?", 2)
	hostPort := hostPortAndParams[0]
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("invalid host:port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %v", err)
	}

	cfg := &VLessConfig{
		UUID:    uuid,
		Address: host,
		Port:    port,
		Params:  make(map[string]string),
	}

	if len(hostPortAndParams) > 1 {
		paramsPart := hostPortAndParams[1]
		paramsAndName := strings.SplitN(paramsPart, "#", 2)
		for param := range strings.SplitSeq(paramsAndName[0], "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 {
				cfg.Params[kv[0]] = kv[1]
			}
		}
	}
	return cfg, nil
}

// Generate Xray configuration
func buildXrayConfig(cfg *VLessConfig, listenAddr, httpAddr string, dns []string, debug bool) ([]byte, error) {
	logLevel := "error"
	logAccess := "none"
	if debug {
		logLevel = "debug"
		logAccess = ""
	}

	// Outbound settings
	security := cfg.Params["security"]
	if security == "" {
		security = "tls"
	}
	streamSettings := map[string]any{
		"network": cfg.Params["type"],
	}
	if cfg.Params["type"] == "" {
		streamSettings["network"] = "tcp"
	}

	switch security {
	case "tls":
		streamSettings["security"] = "tls"
		tlsSettings := map[string]any{
			"serverName": cfg.Params["sni"],
		}
		if cfg.Params["sni"] == "" {
			tlsSettings["serverName"] = cfg.Address
		}
		if fp := cfg.Params["fp"]; fp != "" {
			tlsSettings["fingerprint"] = fp
		}
		streamSettings["tlsSettings"] = tlsSettings
	case "reality":
		streamSettings["security"] = "reality"
		streamSettings["realitySettings"] = map[string]any{
			"serverName":  cfg.Params["sni"],
			"fingerprint": cfg.Params["fp"],
			"publicKey":   cfg.Params["pbk"],
			"shortId":     cfg.Params["sid"],
		}
	}

	// WebSocket
	if cfg.Params["type"] == "ws" {
		ws := map[string]any{}
		if path := cfg.Params["path"]; path != "" {
			ws["path"] = path
		}
		if host := cfg.Params["host"]; host != "" {
			ws["headers"] = map[string]string{"Host": host}
		}
		streamSettings["wsSettings"] = ws
	}
	// gRPC
	if cfg.Params["type"] == "grpc" {
		streamSettings["grpcSettings"] = map[string]any{
			"serviceName": cfg.Params["serviceName"],
		}
	}

	// Inbounds
	var inbounds []any
	listenHost, listenPortStr, _ := net.SplitHostPort(listenAddr)
	listenPort, _ := strconv.Atoi(listenPortStr)

	// Always: SOCKS5 on listenAddr
	inbounds = append(inbounds, map[string]any{
		"listen":   listenHost,
		"port":     listenPort,
		"protocol": "socks",
		"settings": map[string]any{"udp": true},
		"sniffing": map[string]any{
			"enabled":      true,
			"destOverride": []string{"http", "tls"},
		},
	})

	// Optional: HTTP on httpAddr
	if httpAddr != "" {
		httpHost, httpPortStr, _ := net.SplitHostPort(httpAddr)
		httpPort, _ := strconv.Atoi(httpPortStr)
		inbounds = append(inbounds, map[string]any{
			"listen":   httpHost,
			"port":     httpPort,
			"protocol": "http",
			"settings": map[string]any{"timeout": 0},
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": []string{"http", "tls"},
			},
		})
	}

	// Full configuration
	configJSON := map[string]any{
		"log":   map[string]any{"loglevel": logLevel, "access": logAccess},
		"stats": map[string]any{},
		"dns": map[string]any{
			"servers": dns,
		},
		"policy": map[string]any{
			"system": map[string]any{
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{
				"tag":      "proxy",
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": cfg.Address,
							"port":    cfg.Port,
							"users": []any{
								map[string]any{
									"id":         cfg.UUID,
									"encryption": cfg.Params["encryption"],
									"flow":       cfg.Params["flow"],
								},
							},
						},
					},
				},
				"streamSettings": streamSettings,
			},
		},
	}
	return json.MarshalIndent(configJSON, "", "  ")
}

func main() {
	// VLESS flag
	link := flag.String("link", "", "VLESS link (used if no WireGuard config is provided)")
	// WG from file
	wgConfigPath := flag.String("wg", "", "Path to WireGuard config file. Overridden by individual wg-* flags.")
	// WG from flags
	wgPrivateKey := flag.String("wg-private-key", "", "WireGuard private key")
	wgPublicKey := flag.String("wg-public-key", "", "WireGuard peer public key")
	wgPresharedKey := flag.String("wg-preshared-key", "", "WireGuard preshared key (optional)")
	wgEndpoint := flag.String("wg-endpoint", "", "WireGuard peer endpoint (host:port)")
	wgAddress := flag.String("wg-address", "", "WireGuard interface addresses, comma-separated (e.g. 10.0.0.2/32)")
	wgMTU := flag.Int("wg-mtu", 0, "WireGuard MTU (optional)")
	wgKeepAlive := flag.Int("wg-keepalive", 0, "WireGuard persistent keepalive in seconds (optional)")

	// Common flags
	listen := flag.String("listen", "", "Proxy listen address ip:port — handles SOCKS5 and HTTP (required)")
	httpSep := flag.String("http", "", "Optional: separate HTTP proxy ip:port")
	dnsServers := flag.String("dns", "8.8.8.8,1.1.1.1", "Comma-separated list of DNS servers (e.g. 8.8.8.8,1.1.1.1)")
	localAddress := flag.String("local-address", "", "Optional: override destination address (host:port) to connect to. Only for VLESS.")
	debug := flag.Bool("debug", false, "Enable debug logging for xray-core")
	metricsListen := flag.String("metrics", "", "Optional: address to expose HTTP metrics endpoint (e.g. 127.0.0.1:8080)")
	flag.Parse()

	if *listen == "" {
		log.Fatal("-listen is required")
	}

	var dnsList []string
	for s := range strings.SplitSeq(*dnsServers, ",") {
		if s = strings.TrimSpace(s); s != "" {
			dnsList = append(dnsList, s)
		}
	}

	var jsonConfig []byte
	var err error

	// Determine mode based on flags (flags > file > link)
	useWgFlags := *wgPrivateKey != "" && *wgPublicKey != "" && *wgEndpoint != ""

	if useWgFlags {
		// Mode 1: WireGuard from flags (highest priority)
		log.Println("Using WireGuard config from flags")

		var addrs []string
		if *wgAddress != "" {
			for addr := range strings.SplitSeq(*wgAddress, ",") {
				addrs = append(addrs, strings.TrimSpace(addr))
			}
		}

		iface := &WireGuardInterfaceConfig{
			PrivateKey: *wgPrivateKey,
			Address:    addrs,
			MTU:        *wgMTU,
		}
		peer := &WireGuardPeerConfig{
			PublicKey:    *wgPublicKey,
			PresharedKey: *wgPresharedKey,
			Endpoint:     *wgEndpoint,
			KeepAlive:    *wgKeepAlive,
		}
		jsonConfig, err = buildWireGuardXrayConfig(iface, peer, *listen, *httpSep, dnsList, *debug)
		if err != nil {
			log.Fatal("Failed to build WireGuard Xray configuration from flags:", err)
		}
	} else if *wgConfigPath != "" {
		// Mode 2: WireGuard from config file
		log.Printf("Using WireGuard config from %s", *wgConfigPath)
		iface, peer, err := parseWireGuardConfig(*wgConfigPath)
		if err != nil {
			log.Fatalf("Failed to parse WireGuard config %s: %v", *wgConfigPath, err)
		}
		jsonConfig, err = buildWireGuardXrayConfig(iface, peer, *listen, *httpSep, dnsList, *debug)
		if err != nil {
			log.Fatal("Failed to build WireGuard Xray configuration from file:", err)
		}
	} else if *link != "" {
		// Mode 3: VLESS from link
		log.Println("Using VLESS config from link")
		cfg, err := parseVLessLink(*link)
		if err != nil {
			log.Fatal("Failed to parse VLESS link:", err)
		}

		if *localAddress != "" {
			host, portStr, err := net.SplitHostPort(*localAddress)
			if err != nil {
				log.Fatalf("Invalid -local-address %q: %v", *localAddress, err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				log.Fatalf("Invalid port in -local-address %q: %v", *localAddress, err)
			}
			cfg.Address = host
			cfg.Port = port
		}
		jsonConfig, err = buildXrayConfig(cfg, *listen, *httpSep, dnsList, *debug)
		if err != nil {
			log.Fatal("Failed to build VLESS Xray configuration:", err)
		}
	} else {
		log.Fatal("No configuration provided. Use -link (for VLESS), -wg (for WireGuard file), or wg-* flags.")
	}

	// Load config using serial.LoadJSONConfig (requires io.Reader)
	config, err := serial.LoadJSONConfig(strings.NewReader(string(jsonConfig)))
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	server, err := core.New(config)
	if err != nil {
		log.Fatal("Failed to create Xray instance:", err)
	}

	if err := server.Start(); err != nil {
		log.Fatal("Failed to start Xray:", err)
	}

	log.Printf("Xray started -> proxy on %s", *listen)
	if *httpSep != "" {
		log.Printf("                HTTP on %s", *httpSep)
	}

	if *metricsListen != "" {
		go func() {
			http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
				var rx, tx int64

				// Извлекаем менеджер статистики напрямую из ядра
				st := server.GetFeature(stats.ManagerType())
				if sm, ok := st.(stats.Manager); ok {
					// rx (downlink) - скачано
					if c := sm.GetCounter("outbound>>>proxy>>>traffic>>>downlink"); c != nil {
						rx = c.Value()
					}
					// tx (uplink) - отдано
					if c := sm.GetCounter("outbound>>>proxy>>>traffic>>>uplink"); c != nil {
						tx = c.Value()
					}
				}

				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				// Формат, совместимый с wireproxy
				fmt.Fprintf(w, "tx_bytes=%d\nrx_bytes=%d\n", tx, rx)
			})
			if *debug {
				log.Printf("Metrics API listening on http://%s/metrics", *metricsListen)
			}
			if err := http.ListenAndServe(*metricsListen, nil); err != nil {
				log.Println("Metrics HTTP server error:", err)
			}
		}()
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	server.Close()
	log.Println("Xray stopped")
}

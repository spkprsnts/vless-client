package main

import (
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
)

type VLessConfig struct {
	UUID    string
	Address string
	Port    int
	Params  map[string]string
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
		paramsList := strings.Split(paramsAndName[0], "&")
		for _, param := range paramsList {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) == 2 {
				cfg.Params[kv[0]] = kv[1]
			}
		}
	}
	return cfg, nil
}

// Generate Xray configuration
func buildXrayConfig(cfg *VLessConfig, listenAddr, httpAddr string, debug bool) ([]byte, error) {
	logLevel := "error"
	if debug {
		logLevel = "debug"
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

	if httpAddr == "" {
		// Mixed mode: one port for SOCKS5 + HTTP
		inbounds = append(inbounds, map[string]any{
			"listen":   listenHost,
			"port":     listenPort,
			"protocol": "http",
			"settings": map[string]any{
				"timeout":          0,
				"allowTransparent": true,
			},
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": []string{"http", "tls"},
			},
		})
	} else {
		// Separate proxies: SOCKS5 on listenAddr, HTTP on httpAddr
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
		"log":   map[string]any{"loglevel": logLevel},
		"stats": map[string]any{},
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
	link := flag.String("link", "", "VLESS link (required)")
	listen := flag.String("listen", "", "Address ip:port for mixed proxy (SOCKS5+HTTP) (required)")
	httpSep := flag.String("http", "", "Optional: separate HTTP proxy ip:port (then -listen will be only SOCKS5)")
	localAddress := flag.String("local-address", "", "Optional: override destination address (host:port) to connect to")
	debug := flag.Bool("debug", false, "Enable debug logging for xray-core")
	metricsListen := flag.String("metrics", "", "Optional: address to expose HTTP metrics endpoint (e.g. 127.0.0.1:8080)")
	flag.Parse()

	if *link == "" || *listen == "" {
		log.Fatal("Both -link and -listen are required")
	}

	cfg, err := parseVLessLink(*link)
	if err != nil {
		log.Fatal("Failed to parse VLESS link:", err)
	}

	if *localAddress != "" {
		host, portStr, err := net.SplitHostPort(*localAddress)
		if err != nil {
			log.Fatal("Invalid -local-address format (expected host:port): ", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			log.Fatal("Invalid port in -local-address: ", err)
		}

		// Сохраняем оригинальный адрес для SNI (если он не был задан параметром), перед его перезаписью
		if cfg.Params["sni"] == "" {
			cfg.Params["sni"] = cfg.Address
		}

		cfg.Address = host
		cfg.Port = port
	}

	jsonConfig, err := buildXrayConfig(cfg, *listen, *httpSep, *debug)
	if err != nil {
		log.Fatal("Failed to build configuration:", err)
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

	if *httpSep == "" {
		log.Printf("Xray started -> Listening on %s (SOCKS5+HTTP)", *listen)
	} else {
		log.Printf("Xray started -> Listening on %s (SOCKS5) and %s (HTTP)", *listen, *httpSep)
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

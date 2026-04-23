package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
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
func buildXrayConfig(cfg *VLessConfig, listenAddr, httpAddr string) ([]byte, error) {
	// Outbound settings
	security := cfg.Params["security"]
	if security == "" {
		security = "tls"
	}
	streamSettings := map[string]interface{}{
		"network": cfg.Params["type"],
	}
	if cfg.Params["type"] == "" {
		streamSettings["network"] = "tcp"
	}

	if security == "tls" {
		streamSettings["security"] = "tls"
		tlsSettings := map[string]interface{}{
			"serverName": cfg.Params["sni"],
		}
		if cfg.Params["sni"] == "" {
			tlsSettings["serverName"] = cfg.Address
		}
		if fp := cfg.Params["fp"]; fp != "" {
			tlsSettings["fingerprint"] = fp
		}
		streamSettings["tlsSettings"] = tlsSettings
	} else if security == "reality" {
		streamSettings["security"] = "reality"
		streamSettings["realitySettings"] = map[string]interface{}{
			"serverName":  cfg.Params["sni"],
			"fingerprint": cfg.Params["fp"],
			"publicKey":   cfg.Params["pbk"],
			"shortId":     cfg.Params["sid"],
		}
	}

	// WebSocket
	if cfg.Params["type"] == "ws" {
		ws := map[string]interface{}{}
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
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": cfg.Params["serviceName"],
		}
	}

	// Inbounds
	var inbounds []interface{}
	listenHost, listenPortStr, _ := net.SplitHostPort(listenAddr)
	listenPort, _ := strconv.Atoi(listenPortStr)

	if httpAddr == "" {
		// Mixed mode: one port for SOCKS5 + HTTP
		inbounds = append(inbounds, map[string]interface{}{
			"listen":   listenHost,
			"port":     listenPort,
			"protocol": "http",
			"settings": map[string]interface{}{
				"timeout":          0,
				"allowTransparent": true,
			},
			"sniffing": map[string]interface{}{
				"enabled":      true,
				"destOverride": []string{"http", "tls"},
			},
		})
	} else {
		// Separate proxies: SOCKS5 on listenAddr, HTTP on httpAddr
		inbounds = append(inbounds, map[string]interface{}{
			"listen":   listenHost,
			"port":     listenPort,
			"protocol": "socks",
			"settings": map[string]interface{}{"udp": true},
			"sniffing": map[string]interface{}{
				"enabled":      true,
				"destOverride": []string{"http", "tls"},
			},
		})
		httpHost, httpPortStr, _ := net.SplitHostPort(httpAddr)
		httpPort, _ := strconv.Atoi(httpPortStr)
		inbounds = append(inbounds, map[string]interface{}{
			"listen":   httpHost,
			"port":     httpPort,
			"protocol": "http",
			"settings": map[string]interface{}{"timeout": 0},
			"sniffing": map[string]interface{}{
				"enabled":      true,
				"destOverride": []string{"http", "tls"},
			},
		})
	}

	// Full configuration
	configJSON := map[string]interface{}{
		"log":      map[string]interface{}{"loglevel": "warning"},
		"inbounds": inbounds,
		"outbounds": []interface{}{
			map[string]interface{}{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []interface{}{
						map[string]interface{}{
							"address": cfg.Address,
							"port":    cfg.Port,
							"users": []interface{}{
								map[string]interface{}{
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

	jsonConfig, err := buildXrayConfig(cfg, *listen, *httpSep)
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
		log.Printf("Mixed proxy (SOCKS5+HTTP) is running on %s", *listen)
	} else {
		log.Printf("SOCKS5 proxy on %s, HTTP proxy on %s", *listen, *httpSep)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	server.Close()
	log.Println("Client stopped")
}

// Package config loads server configuration from environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all runtime settings for the BOLTUN relay server.
type Config struct {
	// ListenAddr is the TCP address to listen on, e.g. ":8443".
	ListenAddr string
	// DevMode disables TLS and prints an explicit warning. Never use it
	// for a public deployment.
	DevMode bool
	// TLSCertFile / TLSKeyFile are required when DevMode == false.
	TLSCertFile string
	TLSKeyFile  string

	// MaxConnections caps simultaneously connected clients.
	MaxConnections int
	// MaxPacketBytes caps a single inbound packet (see protocol.MaxPacketSize).
	MaxPacketBytes int
	// ReadTimeout / WriteTimeout are WebSocket IO deadlines.
	ReadTimeout time.Duration
	// PingInterval is how often the server sends PING packets.
	PingInterval time.Duration
	// HandshakeTimeout limits the WS upgrade phase.
	HandshakeTimeout time.Duration
	// StoreFile is the JSON file backing offline message storage.
	// Empty string means in-memory only (messages are lost on restart).
	StoreFile string
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer, got %q", key, v)
	}
	return n, nil
}

func envDur(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be a duration, got %q", key, v)
	}
	return d, nil
}

// Load reads configuration from BOLTUN_* environment variables.
//
//	BOLTUN_DEV_MODE        "true" to run without TLS (LOCAL DEVELOPMENT ONLY)
//	BOLTUN_LISTEN_ADDR     default ":8443"
//	BOLTUN_TLS_CERT_FILE   required unless dev mode
//	BOLTUN_TLS_KEY_FILE    required unless dev mode
//	BOLTUN_MAX_CONNECTIONS default 1024
//	BOLTUN_READ_TIMEOUT    default "70s"
//	BOLTUN_PING_INTERVAL   default "25s"
func Load() (*Config, error) {
	devRaw := envStr("BOLTUN_DEV_MODE", "")
	devMode := devRaw == "true" || devRaw == "1"

	c := &Config{
		DevMode:       devMode,
		ListenAddr:    envStr("BOLTUN_LISTEN_ADDR", ":8443"),
		TLSCertFile:   envStr("BOLTUN_TLS_CERT_FILE", ""),
		TLSKeyFile:    envStr("BOLTUN_TLS_KEY_FILE", ""),
		PingInterval:  25 * time.Second,
		ReadTimeout:   70 * time.Second,
	}

	var err error
	if c.MaxConnections, err = envInt("BOLTUN_MAX_CONNECTIONS", 1024); err != nil {
		return nil, err
	}
	if c.MaxPacketBytes, err = envInt("BOLTUN_MAX_PACKET_BYTES", 256*1024); err != nil {
		return nil, err
	}
	if c.ReadTimeout, err = envDur("BOLTUN_READ_TIMEOUT", c.ReadTimeout); err != nil {
		return nil, err
	}
	if c.PingInterval, err = envDur("BOLTUN_PING_INTERVAL", c.PingInterval); err != nil {
		return nil, err
	}
	if c.HandshakeTimeout, err = envDur("BOLTUN_HANDSHAKE_TIMEOUT", 10*time.Second); err != nil {
		return nil, err
	}

	if !c.DevMode && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
		return nil, fmt.Errorf("config: TLS cert/key required (set BOLTUN_TLS_CERT_FILE and BOLTUN_TLS_KEY_FILE, or BOLTUN_DEV_MODE=true for local development only)")
	}
	if c.MaxConnections <= 0 {
		return nil, fmt.Errorf("config: BOLTUN_MAX_CONNECTIONS must be positive")
	}
	if c.MaxPacketBytes <= 0 || c.MaxPacketBytes > 1<<20 {
		return nil, fmt.Errorf("config: BOLTUN_MAX_PACKET_BYTES must be in (0, 1MiB]")
	}
	return c, nil
}

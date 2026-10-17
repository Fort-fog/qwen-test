// BOLTUN relay server.
//
// Runs WITHOUT root privileges (bind ports >1024 by default).
// Local development:  BOLTUN_DEV_MODE=true go run ./cmd/boltun-server
// Production:         set BOLTUN_TLS_CERT_FILE / BOLTUN_TLS_KEY_FILE (WSS).
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/boltun/server/internal/config"
	"github.com/boltun/server/internal/devices"
	"github.com/boltun/server/internal/protocol"
	"github.com/boltun/server/internal/relay"
	"github.com/boltun/server/internal/store"
	"github.com/boltun/server/internal/transport"
)

func main() {
	shutdownGrace := flag.Duration("grace", 10*time.Second, "graceful shutdown window")
	flag.Parse()

	logger := log.New(os.Stdout, "[boltun] ", log.LstdFlags|log.Lmsgprefix)

	cfg, err := config.Load()
	if err != nil {
		logger.Printf("FATAL config: %v", err)
		os.Exit(1)
	}

	if cfg.StoreFile != "" {
		if err := store.EnsureDir(cfg.StoreFile); err != nil {
			logger.Printf("FATAL store dir: %v", err)
			os.Exit(1)
		}
	}
	st, err := store.Open(cfg.StoreFile)
	if err != nil {
		logger.Printf("FATAL store open: %v", err)
		os.Exit(1)
	}

	reg := devices.NewRegistry()
	rly := relay.New(reg, st, logger, cfg.MaxPacketBytes)
	srv := transport.New(cfg, rly, logger)

	errCh := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s (dev_mode=%v, protocol v%d, max_packet=%d bytes, max_conns=%d)",
			cfg.ListenAddr, cfg.DevMode, protocol.ProtocolVersion, cfg.MaxPacketBytes, cfg.MaxConnections)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		logger.Printf("FATAL serve: %v", err)
		os.Exit(1)
	case s := <-sig:
		logger.Printf("signal %v received, shutting down gracefully...", s)
		ctx, cancel := context.WithTimeout(context.Background(), *shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			logger.Printf("shutdown error: %v", err)
			os.Exit(1)
		}
		logger.Printf("server stopped cleanly")
	}
}

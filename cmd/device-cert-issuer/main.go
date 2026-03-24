package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"device-cert-issuer/internal/app"
	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/infra/signer"
	"device-cert-issuer/internal/infra/storage"
	httptransport "device-cert-issuer/internal/transport/http"
)

func main() {
	if err := run(); err != nil {
		slog.Error("service terminated", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.Log.Level),
	}))

	db, err := storage.OpenMySQL(cfg.Database.DSN)
	if err != nil {
		return err
	}
	defer func() {
		_ = db.Close()
	}()

	certificateSigner, err := newSigner(cfg)
	if err != nil {
		return err
	}

	handler, err := app.New(cfg, logger, db, certificateSigner)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:           httptransport.NewHTTPHandler(handler, cfg.Server.RequestBodyLimit),
		ReadTimeout:       cfg.Server.ReadTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting HTTP server", slog.String("addr", server.Addr))
		if serveErr := server.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
		close(errCh)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case serveErr := <-errCh:
		return serveErr
	}
}

func newSigner(cfg config.Config) (signer.CertificateSigner, error) {
	switch cfg.Signer.Mode {
	case "file":
		return signer.NewFileSigner(cfg.Signer)
	default:
		return nil, fmt.Errorf("unsupported signer mode: %s", cfg.Signer.Mode)
	}
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

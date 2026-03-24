package config_test

import (
	"testing"
	"time"

	"device-cert-issuer/internal/config"
)

func TestLoad_환경값을_구조체로_로드한다(t *testing.T) {
	t.Setenv("MYSQL_DSN", "user:pass@tcp(localhost:3306)/device_cert_issuer")
	t.Setenv("INTERMEDIATE_CERT_PATH", "/tmp/intermediate.cert.pem")
	t.Setenv("INTERMEDIATE_PRIVATE_KEY_PATH", "/tmp/intermediate.key.pem")
	t.Setenv("INTERMEDIATE_PRIVATE_KEY_PASSPHRASE", "changeit")
	t.Setenv("CERT_VALIDITY", "24h")
	t.Setenv("ALLOWED_RSA_BITS", "2048,4096")
	t.Setenv("ALLOWED_PROFILES", "default,restricted")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Database.DSN == "" {
		t.Fatal("expected dsn to be loaded")
	}
	if cfg.Issuance.Validity != 24*time.Hour {
		t.Fatalf("expected 24h validity, got %s", cfg.Issuance.Validity)
	}
	if len(cfg.Issuance.AllowedRSABits) != 2 {
		t.Fatalf("expected 2 rsa bit values, got %d", len(cfg.Issuance.AllowedRSABits))
	}
	if cfg.Issuance.AllowedProfiles[1] != "restricted" {
		t.Fatalf("expected second profile to be restricted, got %q", cfg.Issuance.AllowedProfiles[1])
	}
}

func TestLoad_파일_사이너는_개인키_경로가_필수다(t *testing.T) {
	t.Setenv("MYSQL_DSN", "user:pass@tcp(localhost:3306)/device_cert_issuer")
	t.Setenv("INTERMEDIATE_CERT_PATH", "/tmp/intermediate.cert.pem")
	t.Setenv("SIGNER_MODE", "file")
	t.Setenv("INTERMEDIATE_PRIVATE_KEY_PATH", "")
	t.Setenv("INTERMEDIATE_PRIVATE_KEY_PASSPHRASE", "changeit")

	if _, err := config.Load(); err == nil {
		t.Fatal("expected error when private key path is missing")
	}
}

func TestLoad_파일_사이너는_패스프레이즈가_필수다(t *testing.T) {
	t.Setenv("MYSQL_DSN", "user:pass@tcp(localhost:3306)/device_cert_issuer")
	t.Setenv("INTERMEDIATE_CERT_PATH", "/tmp/intermediate.cert.pem")
	t.Setenv("INTERMEDIATE_PRIVATE_KEY_PATH", "/tmp/intermediate.key.pem")
	t.Setenv("SIGNER_MODE", "file")
	t.Setenv("INTERMEDIATE_PRIVATE_KEY_PASSPHRASE", "")

	if _, err := config.Load(); err == nil {
		t.Fatal("expected error when passphrase is missing")
	}
}

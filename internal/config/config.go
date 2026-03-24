package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

const (
	defaultBodyLimitBytes = 32768
	defaultProfile        = "default"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Signer   SignerConfig
	Issuance IssuanceConfig
	Log      LogConfig
}

type ServerConfig struct {
	Port              int           `env:"SERVER_PORT" envDefault:"8080"`
	ReadTimeout       time.Duration `env:"SERVER_READ_TIMEOUT" envDefault:"5s"`
	ReadHeaderTimeout time.Duration `env:"SERVER_READ_HEADER_TIMEOUT" envDefault:"2s"`
	WriteTimeout      time.Duration `env:"SERVER_WRITE_TIMEOUT" envDefault:"10s"`
	IdleTimeout       time.Duration `env:"SERVER_IDLE_TIMEOUT" envDefault:"30s"`
	ShutdownTimeout   time.Duration `env:"SERVER_SHUTDOWN_TIMEOUT" envDefault:"10s"`
	RequestBodyLimit  int64         `env:"SERVER_REQUEST_BODY_LIMIT" envDefault:"32768"`
}

type DatabaseConfig struct {
	DSN string `env:"MYSQL_DSN,required"`
}

type SignerConfig struct {
	Mode                    string `env:"SIGNER_MODE" envDefault:"file"`
	IntermediateCertPath    string `env:"INTERMEDIATE_CERT_PATH,required"`
	IntermediatePrivateKey  string `env:"INTERMEDIATE_PRIVATE_KEY_PATH"`
	PrivateKeyPassphrase    string `env:"INTERMEDIATE_PRIVATE_KEY_PASSPHRASE"`
	IntermediateChainPath   string `env:"INTERMEDIATE_CHAIN_PATH"`
	RequirePrivateKeyStrict bool   `env:"SIGNER_STRICT_FILE_PERMS" envDefault:"true"`
}

type IssuanceConfig struct {
	Validity          time.Duration
	AllowedKeyAlgos   []string
	AllowedCurves     []string
	AllowedRSABits    []int
	DefaultProfile    string
	AllowedProfiles   []string
	SubjectOrg        string
	SubjectOrgUnit    string
	SubjectCountry    string
	SubjectProvince   string
	SubjectLocality   string
	SubjectCommonName string
}

type LogConfig struct {
	Level string `env:"LOG_LEVEL" envDefault:"INFO"`
}

type rawConfig struct {
	ServerPort               int           `env:"SERVER_PORT" envDefault:"8080"`
	ServerReadTimeout        time.Duration `env:"SERVER_READ_TIMEOUT" envDefault:"5s"`
	ServerReadHeaderTimeout  time.Duration `env:"SERVER_READ_HEADER_TIMEOUT" envDefault:"2s"`
	ServerWriteTimeout       time.Duration `env:"SERVER_WRITE_TIMEOUT" envDefault:"10s"`
	ServerIdleTimeout        time.Duration `env:"SERVER_IDLE_TIMEOUT" envDefault:"30s"`
	ServerShutdownTimeout    time.Duration `env:"SERVER_SHUTDOWN_TIMEOUT" envDefault:"10s"`
	ServerRequestBodyLimit   int64         `env:"SERVER_REQUEST_BODY_LIMIT" envDefault:"32768"`
	MySQLDSN                 string        `env:"MYSQL_DSN,required"`
	SignerMode               string        `env:"SIGNER_MODE" envDefault:"file"`
	IntermediateCertPath     string        `env:"INTERMEDIATE_CERT_PATH,required"`
	IntermediatePrivateKey   string        `env:"INTERMEDIATE_PRIVATE_KEY_PATH"`
	PrivateKeyPassphrase     string        `env:"INTERMEDIATE_PRIVATE_KEY_PASSPHRASE"`
	IntermediateChainPath    string        `env:"INTERMEDIATE_CHAIN_PATH"`
	SignerStrictFilePerms    bool          `env:"SIGNER_STRICT_FILE_PERMS" envDefault:"true"`
	CertValidity             time.Duration `env:"CERT_VALIDITY" envDefault:"720h"`
	AllowedKeyAlgorithms     string        `env:"ALLOWED_KEY_ALGORITHMS" envDefault:"RSA,ECDSA,Ed25519"`
	AllowedCurves            string        `env:"ALLOWED_CURVES" envDefault:"P256,P384,Ed25519"`
	AllowedRSABits           string        `env:"ALLOWED_RSA_BITS" envDefault:"2048,3072,4096"`
	DefaultProfile           string        `env:"DEFAULT_PROFILE" envDefault:"default"`
	AllowedProfiles          string        `env:"ALLOWED_PROFILES" envDefault:"default"`
	IssuerOrganization       string        `env:"ISSUER_ORGANIZATION" envDefault:"Device PKI"`
	IssuerOrganizationalUnit string        `env:"ISSUER_ORGANIZATIONAL_UNIT" envDefault:"Device Certificates"`
	IssuerCountry            string        `env:"ISSUER_COUNTRY" envDefault:"KR"`
	IssuerProvince           string        `env:"ISSUER_PROVINCE" envDefault:"Seoul"`
	IssuerLocality           string        `env:"ISSUER_LOCALITY" envDefault:"Seoul"`
	IssuerCommonName         string        `env:"ISSUER_COMMON_NAME" envDefault:"Device Certificate"`
	LogLevel                 string        `env:"LOG_LEVEL" envDefault:"INFO"`
}

func Load() (Config, error) {
	var raw rawConfig
	if err := env.Parse(&raw); err != nil {
		return Config{}, fmt.Errorf("parse env: %w", err)
	}

	allowedRSABits, err := parseIntList(raw.AllowedRSABits)
	if err != nil {
		return Config{}, fmt.Errorf("parse ALLOWED_RSA_BITS: %w", err)
	}

	cfg := Config{
		Server: ServerConfig{
			Port:              raw.ServerPort,
			ReadTimeout:       raw.ServerReadTimeout,
			ReadHeaderTimeout: raw.ServerReadHeaderTimeout,
			WriteTimeout:      raw.ServerWriteTimeout,
			IdleTimeout:       raw.ServerIdleTimeout,
			ShutdownTimeout:   raw.ServerShutdownTimeout,
			RequestBodyLimit:  raw.ServerRequestBodyLimit,
		},
		Database: DatabaseConfig{
			DSN: normalizeEnvString(raw.MySQLDSN),
		},
		Signer: SignerConfig{
			Mode:                    normalizeEnvString(raw.SignerMode),
			IntermediateCertPath:    normalizeEnvString(raw.IntermediateCertPath),
			IntermediatePrivateKey:  normalizeEnvString(raw.IntermediatePrivateKey),
			PrivateKeyPassphrase:    normalizeEnvString(raw.PrivateKeyPassphrase),
			IntermediateChainPath:   normalizeEnvString(raw.IntermediateChainPath),
			RequirePrivateKeyStrict: raw.SignerStrictFilePerms,
		},
		Issuance: IssuanceConfig{
			Validity:          raw.CertValidity,
			AllowedKeyAlgos:   parseStringList(raw.AllowedKeyAlgorithms),
			AllowedCurves:     parseStringList(raw.AllowedCurves),
			AllowedRSABits:    allowedRSABits,
			DefaultProfile:    normalizeProfile(raw.DefaultProfile),
			AllowedProfiles:   parseStringList(raw.AllowedProfiles),
			SubjectOrg:        normalizeEnvString(raw.IssuerOrganization),
			SubjectOrgUnit:    normalizeEnvString(raw.IssuerOrganizationalUnit),
			SubjectCountry:    normalizeEnvString(raw.IssuerCountry),
			SubjectProvince:   normalizeEnvString(raw.IssuerProvince),
			SubjectLocality:   normalizeEnvString(raw.IssuerLocality),
			SubjectCommonName: normalizeEnvString(raw.IssuerCommonName),
		},
		Log: LogConfig{
			Level: normalizeEnvString(raw.LogLevel),
		},
	}

	if cfg.Server.RequestBodyLimit <= 0 {
		cfg.Server.RequestBodyLimit = defaultBodyLimitBytes
	}

	if cfg.Issuance.DefaultProfile == "" {
		cfg.Issuance.DefaultProfile = defaultProfile
	}

	if cfg.Signer.Mode == "file" && cfg.Signer.IntermediatePrivateKey == "" {
		return Config{}, fmt.Errorf("INTERMEDIATE_PRIVATE_KEY_PATH is required when SIGNER_MODE=file")
	}
	if cfg.Signer.Mode == "file" && cfg.Signer.PrivateKeyPassphrase == "" {
		return Config{}, fmt.Errorf("INTERMEDIATE_PRIVATE_KEY_PASSPHRASE is required when SIGNER_MODE=file")
	}

	return cfg, nil
}

func parseStringList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}

	parts := strings.Split(v, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}

	return result
}

func parseIntList(v string) ([]int, error) {
	parts := parseStringList(v)
	result := make([]int, 0, len(parts))
	for _, part := range parts {
		var value int
		if _, err := fmt.Sscanf(part, "%d", &value); err != nil {
			return nil, err
		}
		result = append(result, value)
	}

	return result, nil
}

func normalizeProfile(v string) string {
	trimmed := normalizeEnvString(v)
	if trimmed == "" {
		return defaultProfile
	}

	return trimmed
}

func normalizeEnvString(v string) string {
	trimmed := strings.TrimSpace(v)
	if len(trimmed) < 2 {
		return trimmed
	}

	if (trimmed[0] == '"' && trimmed[len(trimmed)-1] == '"') || (trimmed[0] == '\'' && trimmed[len(trimmed)-1] == '\'') {
		unquoted, err := strconv.Unquote(trimmed)
		if err == nil {
			return unquoted
		}

		return trimmed[1 : len(trimmed)-1]
	}

	return trimmed
}

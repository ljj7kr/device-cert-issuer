package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/infra/pemutil"

	"github.com/youmark/pkcs8"
)

type CertificateSigner interface {
	Signer() crypto.Signer
	Certificate() *x509.Certificate
	ChainPEM() string
	HealthCheck(context.Context) error
}

type FileSigner struct {
	signer   crypto.Signer
	cert     *x509.Certificate
	chainPEM string
}

func NewFileSigner(cfg config.SignerConfig) (*FileSigner, error) {
	if cfg.IntermediatePrivateKey == "" {
		return nil, fmt.Errorf("file signer requires private key path")
	}

	if cfg.RequirePrivateKeyStrict {
		if err := validatePrivateKeyPermissions(cfg.IntermediatePrivateKey); err != nil {
			return nil, err
		}
	}

	certPEM, err := os.ReadFile(cfg.IntermediateCertPath)
	if err != nil {
		return nil, fmt.Errorf("read intermediate cert: %w", err)
	}

	cert, err := parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate cert: %w", err)
	}

	keyPEM, err := os.ReadFile(cfg.IntermediatePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("read intermediate key: %w", err)
	}

	key, err := parsePrivateKey(keyPEM, cfg.PrivateKeyPassphrase)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate key: %w", err)
	}

	if err := validateCertificateKeyMatch(cert, key); err != nil {
		return nil, fmt.Errorf("validate signer key pair: %w", err)
	}

	chainPEM := string(certPEM)
	if cfg.IntermediateChainPath != "" {
		chainBytes, chainErr := os.ReadFile(cfg.IntermediateChainPath)
		if chainErr != nil {
			return nil, fmt.Errorf("read intermediate chain: %w", chainErr)
		}
		chainPEM = string(chainBytes)
	}

	return &FileSigner{
		signer:   key,
		cert:     cert,
		chainPEM: chainPEM,
	}, nil
}

func (s *FileSigner) Signer() crypto.Signer {
	return s.signer
}

func (s *FileSigner) Certificate() *x509.Certificate {
	return s.cert
}

func (s *FileSigner) ChainPEM() string {
	return s.chainPEM
}

func (s *FileSigner) HealthCheck(context.Context) error {
	if s == nil || s.signer == nil || s.cert == nil {
		return fmt.Errorf("signer not initialized")
	}

	return nil
}

func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, err := pemutil.DecodeSingleBlock(certPEM, "CERTIFICATE")
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func parsePrivateKey(keyPEM []byte, passphrase string) (crypto.Signer, error) {
	block, err := pemutil.DecodeSingleBlock(keyPEM, "")
	if err != nil {
		return nil, err
	}

	if isLegacyOpenSSLPemBlock(block.Headers) {
		return nil, errors.New("legacy OpenSSL PEM encryption is not supported; use encrypted PKCS#8 private key")
	}

	if block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported private key PEM type %q; use ENCRYPTED PRIVATE KEY", block.Type)
	}

	if passphrase == "" {
		return nil, errors.New("encrypted PKCS#8 private key requires INTERMEDIATE_PRIVATE_KEY_PASSPHRASE")
	}

	// 로컬 persisted key format 을 하나로 고정해서 운영 복잡도와 우회 경로를 줄인다
	if err := validateEncryptedPKCS8Profile(block.Bytes); err != nil {
		return nil, err
	}

	key, parseErr := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(passphrase))
	if parseErr != nil {
		return nil, errors.New("failed to decrypt or parse encrypted PKCS#8 private key")
	}

	return asSigner(key)
}

func asSigner(key any) (crypto.Signer, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k, nil
	case ed25519.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
}

func validatePrivateKeyPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat private key: %w", err)
	}

	perm := info.Mode().Perm()
	if perm&fs.FileMode(0o077) != 0 {
		return fmt.Errorf("private key file permissions are too broad")
	}

	return nil
}

func validateCertificateKeyMatch(cert *x509.Certificate, key crypto.Signer) error {
	certPublicKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}

	signerPublicKeyDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("marshal signer public key: %w", err)
	}

	if !bytes.Equal(certPublicKeyDER, signerPublicKeyDER) {
		return errors.New("intermediate certificate public key does not match private key")
	}

	return nil
}

func isLegacyOpenSSLPemBlock(headers map[string]string) bool {
	if len(headers) == 0 {
		return false
	}

	_, hasProcType := headers["Proc-Type"]
	_, hasDEKInfo := headers["DEK-Info"]

	return hasProcType || hasDEKInfo
}

var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt           asn1.RawValue
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

func validateEncryptedPKCS8Profile(der []byte) error {
	var info encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return errors.New("invalid encrypted PKCS#8 structure")
	}

	if !info.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return errors.New("encrypted PKCS#8 private key must use PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC")
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(info.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return errors.New("invalid PBES2 parameters in encrypted PKCS#8 private key")
	}

	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return errors.New("encrypted PKCS#8 private key must use PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC")
	}
	if !params.EncryptionScheme.Algorithm.Equal(oidAES256CBC) {
		return errors.New("encrypted PKCS#8 private key must use PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC")
	}

	var kdfParams pbkdf2Params
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdfParams); err != nil {
		return errors.New("invalid PBKDF2 parameters in encrypted PKCS#8 private key")
	}

	if !kdfParams.PRF.Algorithm.Equal(oidHMACWithSHA256) {
		return errors.New("encrypted PKCS#8 private key must use PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC")
	}

	return nil
}

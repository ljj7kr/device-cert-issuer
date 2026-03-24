package signer_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/infra/signer"

	"github.com/youmark/pkcs8"
)

func TestNewFileSigner_암호화된_PKCS8_개인키를_로드한다(t *testing.T) {
	certPath, keyPath := writeSignerMaterial(t)

	fileSigner, err := signer.NewFileSigner(config.SignerConfig{
		Mode:                   "file",
		IntermediateCertPath:   certPath,
		IntermediatePrivateKey: keyPath,
		PrivateKeyPassphrase:   "changeit",
	})
	if err != nil {
		t.Fatalf("NewFileSigner returned error: %v", err)
	}

	if fileSigner.Certificate().Subject.CommonName != "Intermediate CA" {
		t.Fatalf("unexpected subject: %s", fileSigner.Certificate().Subject.CommonName)
	}
}

func TestNewFileSigner_지원하는_암호화_프로파일만_허용한다(t *testing.T) {
	certPath, keyPath := writeSignerMaterialWithOpts(t, &pkcs8.Opts{
		Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{
			SaltSize:       16,
			IterationCount: 600000,
			HMACHash:       crypto.SHA256,
		},
	})

	fileSigner, err := signer.NewFileSigner(config.SignerConfig{
		Mode:                   "file",
		IntermediateCertPath:   certPath,
		IntermediatePrivateKey: keyPath,
		PrivateKeyPassphrase:   "changeit",
	})
	if err != nil {
		t.Fatalf("NewFileSigner returned error: %v", err)
	}
	if fileSigner.Signer() == nil {
		t.Fatal("expected signer to be initialized")
	}
}

func TestNewFileSigner_잘못된_패스프레이즈를_거부한다(t *testing.T) {
	certPath, keyPath := writeSignerMaterial(t)

	_, err := signer.NewFileSigner(config.SignerConfig{
		Mode:                   "file",
		IntermediateCertPath:   certPath,
		IntermediatePrivateKey: keyPath,
		PrivateKeyPassphrase:   "wrong-passphrase",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed to decrypt or parse encrypted PKCS#8 private key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewFileSigner_지원하지_않는_PKCS8_암호화_프로파일을_거부한다(t *testing.T) {
	testCases := []struct {
		name string
		opts *pkcs8.Opts
	}{
		{
			name: "aes-256-gcm",
			opts: &pkcs8.Opts{
				Cipher: pkcs8.AES256GCM,
				KDFOpts: pkcs8.PBKDF2Opts{
					SaltSize:       16,
					IterationCount: 600000,
					HMACHash:       crypto.SHA256,
				},
			},
		},
		{
			name: "pbkdf2-sha1",
			opts: &pkcs8.Opts{
				Cipher: pkcs8.AES256CBC,
				KDFOpts: pkcs8.PBKDF2Opts{
					SaltSize:       16,
					IterationCount: 600000,
					HMACHash:       crypto.SHA1,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			certPath, keyPath := writeSignerMaterialWithOpts(t, tc.opts)

			_, err := signer.NewFileSigner(config.SignerConfig{
				Mode:                   "file",
				IntermediateCertPath:   certPath,
				IntermediatePrivateKey: keyPath,
				PrivateKeyPassphrase:   "changeit",
			})
			if err == nil {
				t.Fatal("expected encryption profile rejection")
			}
			if !strings.Contains(err.Error(), "encrypted PKCS#8 private key must use PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewFileSigner_인증서와_개인키_불일치를_거부한다(t *testing.T) {
	certPath, _ := writeSignerMaterial(t)
	_, keyPath := writeSignerMaterial(t)

	_, err := signer.NewFileSigner(config.SignerConfig{
		Mode:                   "file",
		IntermediateCertPath:   certPath,
		IntermediatePrivateKey: keyPath,
		PrivateKeyPassphrase:   "changeit",
	})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "intermediate certificate public key does not match private key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewFileSigner_legacy_OpenSSL_PEM_암호화를_거부한다(t *testing.T) {
	dir := t.TempDir()
	certPath, _ := writeSignerMaterial(t)
	keyPath := filepath.Join(dir, "legacy.key.pem")
	legacyPEM := strings.Join([]string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"Proc-Type: 4,ENCRYPTED",
		"DEK-Info: AES-256-CBC,4e80df6e012f3a4633eeaa1c821afb05",
		"",
		"ZmFrZS1lbmNyeXB0ZWQta2V5",
		"-----END RSA PRIVATE KEY-----",
		"",
	}, "\n")
	if err := os.WriteFile(keyPath, []byte(legacyPEM), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err := signer.NewFileSigner(config.SignerConfig{
		Mode:                   "file",
		IntermediateCertPath:   certPath,
		IntermediatePrivateKey: keyPath,
		PrivateKeyPassphrase:   "changeit",
	})
	if err == nil {
		t.Fatal("expected legacy format rejection")
	}
	if !strings.Contains(err.Error(), "legacy OpenSSL PEM encryption is not supported; use encrypted PKCS#8 private key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewFileSigner_평문_개인키_PEM을_거부한다(t *testing.T) {
	dir := t.TempDir()
	key, certDER := newRSAKeyAndCert(t)
	certPath := filepath.Join(dir, "intermediate.cert.pem")
	keyPath := filepath.Join(dir, "intermediate.key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err := signer.NewFileSigner(config.SignerConfig{
		Mode:                   "file",
		IntermediateCertPath:   certPath,
		IntermediatePrivateKey: keyPath,
		PrivateKeyPassphrase:   "changeit",
	})
	if err == nil {
		t.Fatal("expected rejection for unencrypted PEM")
	}
	if !strings.Contains(err.Error(), `unsupported private key PEM type "RSA PRIVATE KEY"; use ENCRYPTED PRIVATE KEY`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewFileSigner_지원하지_않는_PEM_타입을_거부한다(t *testing.T) {
	dir := t.TempDir()
	_, certDER := newRSAKeyAndCert(t)
	certPath := filepath.Join(dir, "intermediate.cert.pem")
	keyPath := filepath.Join(dir, "unsupported.key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")}), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	_, err := signer.NewFileSigner(config.SignerConfig{
		Mode:                   "file",
		IntermediateCertPath:   certPath,
		IntermediatePrivateKey: keyPath,
		PrivateKeyPassphrase:   "changeit",
	})
	if err == nil {
		t.Fatal("expected unsupported type error")
	}
	if !strings.Contains(err.Error(), `unsupported private key PEM type "PUBLIC KEY"; use ENCRYPTED PRIVATE KEY`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeSignerMaterial(t *testing.T) (string, string) {
	t.Helper()

	return writeSignerMaterialWithOpts(t, &pkcs8.Opts{
		Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{
			SaltSize:       16,
			IterationCount: 600000,
			HMACHash:       crypto.SHA256,
		},
	})
}

func writeSignerMaterialWithOpts(t *testing.T, opts *pkcs8.Opts) (string, string) {
	t.Helper()

	dir := t.TempDir()
	key, certDER := newRSAKeyAndCert(t)

	encryptedDER, err := pkcs8.MarshalPrivateKey(key, []byte("changeit"), opts)
	if err != nil {
		t.Fatalf("MarshalPrivateKey returned error: %v", err)
	}

	certPath := filepath.Join(dir, "intermediate.cert.pem")
	keyPath := filepath.Join(dir, "intermediate.key.pem")

	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encryptedDER}), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	return certPath, keyPath
}

func newRSAKeyAndCert(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey returned error: %v", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	return key, der
}

func TestNewFileSigner_패스프레이즈가_없으면_실패한다(t *testing.T) {
	certPath, keyPath := writeSignerMaterial(t)

	_, err := signer.NewFileSigner(config.SignerConfig{
		Mode:                   "file",
		IntermediateCertPath:   certPath,
		IntermediatePrivateKey: keyPath,
	})
	if err == nil {
		t.Fatal("expected passphrase error")
	}
	if !strings.Contains(err.Error(), "encrypted PKCS#8 private key requires INTERMEDIATE_PRIVATE_KEY_PASSPHRASE") {
		t.Fatalf("unexpected error: %v", err)
	}
}

package service_test

import (
	"testing"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/service"
)

func TestServerCSRValidator_정상_Server_CSR을_검증한다(t *testing.T) {
	validator := service.NewServerCSRValidator(config.IssuanceConfig{
		AllowedKeyAlgos: []string{"RSA", "ECDSA", "Ed25519"},
		AllowedCurves:   []string{"P256", "P384", "Ed25519"},
		AllowedRSABits:  []int{2048, 3072, 4096},
	})

	validated, err := validator.Validate(newServerCSR(
		t,
		"gateway.local",
		[]string{"gateway.local"},
		[]string{"10.0.0.10"},
		[]string{"spiffe://gateway/server"},
	))
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if len(validated.Identity.DNSNames) != 1 || validated.Identity.DNSNames[0] != "gateway.local" {
		t.Fatalf("unexpected DNS SANs: %#v", validated.Identity.DNSNames)
	}
	if len(validated.Identity.IPAddresses) != 1 || validated.Identity.IPAddresses[0] != "10.0.0.10" {
		t.Fatalf("unexpected IP SANs: %#v", validated.Identity.IPAddresses)
	}
}

func TestServerCSRValidator_SAN이_없으면_거부한다(t *testing.T) {
	validator := service.NewServerCSRValidator(config.IssuanceConfig{
		AllowedKeyAlgos: []string{"RSA"},
		AllowedRSABits:  []int{2048, 3072, 4096},
	})

	_, err := validator.Validate(newServerCSR(t, "gateway.local", nil, nil, nil))
	if err == nil {
		t.Fatal("expected SAN validation error")
	}
}

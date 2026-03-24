package service_test

import (
	"testing"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/domain"
	"device-cert-issuer/internal/service"
)

func TestCSRValidator_정상_CSR을_검증한다(t *testing.T) {
	validator := service.NewCSRValidator(config.IssuanceConfig{
		AllowedKeyAlgos: []string{"ECDSA", "RSA", "Ed25519"},
		AllowedCurves:   []string{"P256", "P384", "Ed25519"},
		AllowedRSABits:  []int{2048, 3072, 4096},
	})

	req := domain.IssueRequest{
		DeviceID: "device-1",
		TenantID: "tenant-1",
		Model:    "model-a",
		CSRPEM: newECDSACSR(
			t,
			"tenant-1:device-1",
			"device-1.tenant-1.devices.local",
			"spiffe://devices/tenant-1/model-a/device-1",
		),
	}

	validated, err := validator.Validate(req, &domain.EnrollmentRecord{
		DeviceID: "device-1",
		TenantID: "tenant-1",
		Model:    "model-a",
	})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if validated.Identity.CommonName != "tenant-1:device-1" {
		t.Fatalf("unexpected common name: %s", validated.Identity.CommonName)
	}
}

func TestCSRValidator_정책과_다른_SAN을_거부한다(t *testing.T) {
	validator := service.NewCSRValidator(config.IssuanceConfig{
		AllowedKeyAlgos: []string{"ECDSA"},
		AllowedCurves:   []string{"P256"},
	})

	req := domain.IssueRequest{
		DeviceID: "device-1",
		TenantID: "tenant-1",
		Model:    "model-a",
		CSRPEM: newECDSACSR(
			t,
			"tenant-1:device-1",
			"wrong.tenant-1.devices.local",
			"spiffe://devices/tenant-1/model-a/device-1",
		),
	}

	_, err := validator.Validate(req, &domain.EnrollmentRecord{
		DeviceID: "device-1",
		TenantID: "tenant-1",
		Model:    "model-a",
	})
	if err == nil {
		t.Fatal("expected policy violation")
	}
}

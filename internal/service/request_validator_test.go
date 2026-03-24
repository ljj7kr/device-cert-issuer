package service_test

import (
	"testing"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/domain"
	"device-cert-issuer/internal/service"
)

func TestRequestValidator_기본_프로필을_적용한다(t *testing.T) {
	validator := service.NewRequestValidator(config.IssuanceConfig{
		DefaultProfile:  "default",
		AllowedProfiles: []string{"default", "restricted"},
	})

	req, err := validator.Validate(domain.IssueRequest{
		DeviceID: "device-1",
		TenantID: "tenant-1",
		Model:    "model-a",
		CSRPEM:   "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----",
	})
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}

	if req.Profile != "default" {
		t.Fatalf("expected default profile, got %q", req.Profile)
	}
}

func TestRequestValidator_허용되지_않은_프로필을_거부한다(t *testing.T) {
	validator := service.NewRequestValidator(config.IssuanceConfig{
		DefaultProfile:  "default",
		AllowedProfiles: []string{"default"},
	})

	_, err := validator.Validate(domain.IssueRequest{
		DeviceID: "device-1",
		TenantID: "tenant-1",
		Model:    "model-a",
		CSRPEM:   "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----",
		Profile:  "restricted",
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

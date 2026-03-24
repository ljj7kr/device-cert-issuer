package service

import (
	"fmt"
	"strings"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/domain"

	"github.com/go-playground/validator/v10"
)

type requestValidatorInput struct {
	DeviceID string `validate:"required,max=128"`
	TenantID string `validate:"required,max=128"`
	Model    string `validate:"required,max=128"`
	CSRPEM   string `validate:"required,max=16384"`
	Profile  string `validate:"omitempty,max=64"`
}

type RequestValidator struct {
	validate        *validator.Validate
	allowedProfiles map[string]struct{}
	defaultProfile  string
}

func NewRequestValidator(cfg config.IssuanceConfig) *RequestValidator {
	allowedProfiles := make(map[string]struct{}, len(cfg.AllowedProfiles))
	for _, profile := range cfg.AllowedProfiles {
		allowedProfiles[profile] = struct{}{}
	}

	return &RequestValidator{
		validate:        validator.New(validator.WithRequiredStructEnabled()),
		allowedProfiles: allowedProfiles,
		defaultProfile:  cfg.DefaultProfile,
	}
}

func (v *RequestValidator) Validate(req domain.IssueRequest) (domain.IssueRequest, error) {
	req.Profile = strings.TrimSpace(req.Profile)
	if req.Profile == "" {
		req.Profile = v.defaultProfile
	}

	input := requestValidatorInput{
		DeviceID: req.DeviceID,
		TenantID: req.TenantID,
		Model:    req.Model,
		CSRPEM:   req.CSRPEM,
		Profile:  req.Profile,
	}

	if err := v.validate.Struct(input); err != nil {
		return domain.IssueRequest{}, domain.NewAppError("invalid_request", "request validation failed", domain.ErrInvalidRequest, []map[string]string{{"reason": err.Error()}})
	}

	if _, ok := v.allowedProfiles[req.Profile]; !ok {
		return domain.IssueRequest{}, domain.NewAppError("invalid_request", "profile is not allowed", domain.ErrInvalidRequest, []map[string]string{{"field": "profile"}})
	}

	if !strings.Contains(req.CSRPEM, "BEGIN CERTIFICATE REQUEST") {
		return domain.IssueRequest{}, domain.NewAppError("invalid_request", "csr_pem must contain a PEM encoded CSR", domain.ErrInvalidRequest, []map[string]string{{"field": "csr_pem"}})
	}

	return req, nil
}

func ValidationDetails(err error) []map[string]string {
	if err == nil {
		return nil
	}

	return []map[string]string{{"reason": fmt.Sprint(err)}}
}

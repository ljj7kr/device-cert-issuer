package service

import (
	"context"
	"strings"

	"device-cert-issuer/internal/domain"
)

type EnrollmentAuthorizer interface {
	Authorize(ctx context.Context, req domain.IssueRequest) (*domain.EnrollmentRecord, error)
}

type StaticEnrollmentAuthorizer struct{}

func NewStaticEnrollmentAuthorizer() *StaticEnrollmentAuthorizer {
	return &StaticEnrollmentAuthorizer{}
}

func (a *StaticEnrollmentAuthorizer) Authorize(_ context.Context, req domain.IssueRequest) (*domain.EnrollmentRecord, error) {
	if strings.TrimSpace(req.DeviceID) == "" || strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.Model) == "" {
		return nil, domain.NewAppError("unauthorized_device", "device enrollment is not authorized", domain.ErrUnauthorizedDevice, nil)
	}

	return &domain.EnrollmentRecord{
		DeviceID:       req.DeviceID,
		TenantID:       req.TenantID,
		Model:          req.Model,
		AllowedProfile: req.Profile,
	}, nil
}

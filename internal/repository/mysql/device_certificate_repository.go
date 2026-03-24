package mysql

import (
	"context"
	"fmt"

	"device-cert-issuer/internal/gen/sqlc"
	"device-cert-issuer/internal/repository"
)

type DeviceCertificateRepository struct {
	queries *sqlc.Queries
}

func NewDeviceCertificateRepository(queries *sqlc.Queries) *DeviceCertificateRepository {
	return &DeviceCertificateRepository{queries: queries}
}

func (r *DeviceCertificateRepository) Create(ctx context.Context, params repository.CreateDeviceCertificateParams) error {
	_, err := r.queries.CreateDeviceCertificate(ctx, sqlc.CreateDeviceCertificateParams{
		SerialNumber:      params.SerialNumber,
		DeviceID:          params.DeviceID,
		TenantID:          params.TenantID,
		SubjectSummary:    params.SubjectSummary,
		SanSummary:        params.SANSummary,
		FingerprintSha256: params.FingerprintSHA256,
		Profile:           params.Profile,
		IssuanceStatus:    params.IssuanceStatus,
		IssuedAt:          params.IssuedAt,
		ExpiresAt:         params.ExpiresAt,
		CreatedAt:         params.CreatedAt,
		UpdatedAt:         params.UpdatedAt,
	})
	if err != nil {
		return fmt.Errorf("create device certificate: %w", err)
	}

	return nil
}

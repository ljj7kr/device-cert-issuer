package repository

import (
	"context"
	"time"
)

type CreateDeviceCertificateParams struct {
	SerialNumber      string
	DeviceID          string
	TenantID          string
	SubjectSummary    string
	SANSummary        string
	FingerprintSHA256 string
	Profile           string
	IssuanceStatus    string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type DeviceCertificateRepository interface {
	Create(ctx context.Context, params CreateDeviceCertificateParams) error
}

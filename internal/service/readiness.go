package service

import (
	"context"
	"fmt"

	"device-cert-issuer/internal/domain"
	"device-cert-issuer/internal/infra/signer"
)

type DBPinger interface {
	PingContext(ctx context.Context) error
}

type ReadinessService struct {
	signer signer.CertificateSigner
	db     DBPinger
}

func NewReadinessService(signer signer.CertificateSigner, db DBPinger) *ReadinessService {
	return &ReadinessService{
		signer: signer,
		db:     db,
	}
}

func (s *ReadinessService) Check(ctx context.Context) (*domain.ReadinessStatus, error) {
	if s.signer == nil {
		return nil, domain.NewAppError("internal_error", "signer is not configured", domain.ErrNotReady, nil)
	}
	if err := s.signer.HealthCheck(ctx); err != nil {
		return nil, domain.NewAppError("signer_unavailable", "signer is not ready", fmt.Errorf("%w: %w", domain.ErrNotReady, err), nil)
	}
	if s.db == nil {
		return nil, domain.NewAppError("internal_error", "database is not configured", domain.ErrNotReady, nil)
	}
	if err := s.db.PingContext(ctx); err != nil {
		return nil, domain.NewAppError("internal_error", "database is not ready", fmt.Errorf("%w: %w", domain.ErrNotReady, err), nil)
	}

	return &domain.ReadinessStatus{Status: "ready"}, nil
}

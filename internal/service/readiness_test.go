package service_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"

	"device-cert-issuer/internal/domain"
	"device-cert-issuer/internal/service"
)

type readinessSignerStub struct {
	err error
}

func (s *readinessSignerStub) Signer() crypto.Signer {
	return nil
}

func (s *readinessSignerStub) Certificate() *x509.Certificate {
	return &x509.Certificate{}
}

func (s *readinessSignerStub) ChainPEM() string {
	return ""
}

func (s *readinessSignerStub) HealthCheck(context.Context) error {
	return s.err
}

type readinessDBStub struct {
	err error
}

func (d *readinessDBStub) PingContext(context.Context) error {
	return d.err
}

func TestReadinessService_DB_실패를_감지한다(t *testing.T) {
	svc := service.NewReadinessService(&readinessSignerStub{}, &readinessDBStub{err: domain.ErrNotReady})

	_, err := svc.Check(context.Background())
	if err == nil {
		t.Fatal("expected readiness error")
	}
}

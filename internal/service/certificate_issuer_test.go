package service_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/domain"
	"device-cert-issuer/internal/repository"
	"device-cert-issuer/internal/service"
)

type 고정시계 struct {
	now time.Time
}

func (c 고정시계) Now() time.Time {
	return c.now
}

type 고정시리얼 struct{}

func (고정시리얼) NewSerialNumber() (*big.Int, string, error) {
	return big.NewInt(42), "2A", nil
}

type 메모리저장소 struct {
	err error
}

func (r *메모리저장소) Create(_ context.Context, _ repository.CreateDeviceCertificateParams) error {
	return r.err
}

type 테스트사이너 struct {
	cert     *x509.Certificate
	key      crypto.Signer
	chainPEM string
}

func (s *테스트사이너) Signer() crypto.Signer {
	return s.key
}

func (s *테스트사이너) Certificate() *x509.Certificate {
	return s.cert
}

func (s *테스트사이너) ChainPEM() string {
	return s.chainPEM
}

func (s *테스트사이너) HealthCheck(context.Context) error {
	return nil
}

func TestCertificateIssuer_중간_CA_만료일을_넘지_않는다(t *testing.T) {
	cert, key, chainPEM := newSignerMaterial(t)
	fixedNow := cert.NotAfter.Add(-2 * time.Hour)
	issuer := service.NewCertificateIssuer(
		config.IssuanceConfig{
			Validity:        24 * time.Hour,
			SubjectOrg:      "Device PKI",
			SubjectOrgUnit:  "Device Certificates",
			SubjectCountry:  "KR",
			SubjectProvince: "Seoul",
			SubjectLocality: "Seoul",
		},
		고정시계{now: fixedNow},
		고정시리얼{},
		&테스트사이너{cert: cert, key: key, chainPEM: chainPEM},
		&메모리저장소{},
	)

	validated := &domain.ValidatedCSR{
		PublicKey: &key.PublicKey,
		Identity: domain.CSRIdentity{
			CommonName: "tenant-1:device-1",
			DNSNames:   []string{"device-1.tenant-1.devices.local"},
			URIs:       []string{"spiffe://devices/tenant-1/model-a/device-1"},
			SANSummary: "DNS:device-1.tenant-1.devices.local",
		},
	}

	issued, err := issuer.Issue(context.Background(), domain.IssueRequest{
		DeviceID: "device-1",
		TenantID: "tenant-1",
		Model:    "model-a",
		Profile:  "default",
	}, validated)
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	if issued.NotAfter.After(cert.NotAfter) {
		t.Fatalf("issued cert exceeded intermediate validity: %s > %s", issued.NotAfter, cert.NotAfter)
	}
}

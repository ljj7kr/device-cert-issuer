package service_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/domain"
	"device-cert-issuer/internal/repository"
	"device-cert-issuer/internal/service"
)

type 서버메모리저장소 struct {
	err error
}

func (r *서버메모리저장소) Create(_ context.Context, _ repository.CreateDeviceCertificateParams) error {
	return r.err
}

func TestServerCertificateIssuer_ServerAuth_인증서를_발급한다(t *testing.T) {
	cert, key, chainPEM := newSignerMaterial(t)
	issuer := service.NewServerCertificateIssuer(
		config.IssuanceConfig{
			ServerCertValidity: 24 * time.Hour,
			SubjectOrg:         "Device PKI",
			SubjectOrgUnit:     "Server Certificates",
			SubjectCountry:     "KR",
			SubjectProvince:    "Seoul",
			SubjectLocality:    "Seoul",
		},
		고정시계{now: cert.NotBefore.Add(2 * time.Hour)},
		고정시리얼{},
		&테스트사이너{cert: cert, key: key, chainPEM: chainPEM},
		&서버메모리저장소{},
	)

	issued, err := issuer.Issue(context.Background(), &domain.ValidatedCSR{
		PublicKey: &key.PublicKey,
		Identity: domain.CSRIdentity{
			CommonName:     "gateway.local",
			DNSNames:       []string{"gateway.local"},
			IPAddresses:    []string{"10.0.0.10"},
			URIs:           []string{"spiffe://gateway/server"},
			SANSummary:     "DNS:gateway.local,IP:10.0.0.10,URI:spiffe://gateway/server",
			SubjectSummary: "CN=gateway.local",
		},
	})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	if block == nil {
		t.Fatal("expected certificate PEM block")
	}

	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate returned error: %v", err)
	}

	if leaf.IsCA {
		t.Fatal("expected leaf certificate")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("unexpected ext key usage: %#v", leaf.ExtKeyUsage)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "gateway.local" {
		t.Fatalf("unexpected DNS SANs: %#v", leaf.DNSNames)
	}
	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "10.0.0.10" {
		t.Fatalf("unexpected IP SANs: %#v", leaf.IPAddresses)
	}
	if !strings.HasPrefix(issued.FullChainPEM, issued.CertificatePEM) {
		t.Fatal("expected fullchain to start with leaf certificate")
	}
}

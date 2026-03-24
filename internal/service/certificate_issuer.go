package service

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/domain"
	"device-cert-issuer/internal/infra/clock"
	"device-cert-issuer/internal/infra/pemutil"
	"device-cert-issuer/internal/infra/serial"
	"device-cert-issuer/internal/infra/signer"
	"device-cert-issuer/internal/repository"
)

type CertificateIssuer struct {
	cfg        config.IssuanceConfig
	clock      clock.Clock
	serial     serial.Generator
	signer     signer.CertificateSigner
	repository repository.DeviceCertificateRepository
}

func NewCertificateIssuer(
	cfg config.IssuanceConfig,
	clock clock.Clock,
	serial serial.Generator,
	signer signer.CertificateSigner,
	repository repository.DeviceCertificateRepository,
) *CertificateIssuer {
	return &CertificateIssuer{
		cfg:        cfg,
		clock:      clock,
		serial:     serial,
		signer:     signer,
		repository: repository,
	}
}

func (s *CertificateIssuer) Issue(ctx context.Context, req domain.IssueRequest, validatedCSR *domain.ValidatedCSR) (*domain.IssuedCertificate, error) {
	if validatedCSR == nil {
		return nil, domain.NewAppError("internal_error", "validated CSR is required", domain.ErrInternal, nil)
	}

	serialNumber, serialHex, err := s.serial.NewSerialNumber()
	if err != nil {
		return nil, domain.NewAppError("internal_error", "failed to generate serial number", domain.ErrInternal, nil)
	}

	notBefore := s.clock.Now().Add(-1 * time.Minute)
	notAfter := notBefore.Add(s.cfg.Validity)
	if signerNotAfter := s.signer.Certificate().NotAfter.UTC(); notAfter.After(signerNotAfter) {
		notAfter = signerNotAfter
	}
	if !notAfter.After(notBefore) {
		return nil, domain.NewAppError("policy_violation", "certificate validity exceeds issuer validity", domain.ErrPolicyViolation, nil)
	}

	template := s.newCertificateTemplate(req, validatedCSR, serialNumber, notBefore, notAfter)
	der, err := x509.CreateCertificate(
		ctxAwareRandomReader(ctx),
		template,
		s.signer.Certificate(),
		validatedCSR.PublicKey,
		s.signer.Signer(),
	)
	if err != nil {
		return nil, domain.NewAppError("signer_unavailable", "failed to sign certificate", domain.ErrSignerUnavailable, nil)
	}

	deviceCertPEM := pemutil.EncodeCertificateDER(der)
	fingerprint := sha256.Sum256(der)
	issued := &domain.IssuedCertificate{
		DeviceCertificatePEM: deviceCertPEM,
		CertificateChainPEM:  s.signer.ChainPEM(),
		SerialNumber:         serialHex,
		NotBefore:            notBefore,
		NotAfter:             notAfter,
		FingerprintSHA256:    fmt.Sprintf("%x", fingerprint[:]),
		SubjectSummary:       template.Subject.String(),
		SANSummary:           validatedCSR.Identity.SANSummary,
		Profile:              req.Profile,
		IssuanceStatus:       "issued",
	}

	now := s.clock.Now()
	if err := s.repository.Create(ctx, repository.CreateDeviceCertificateParams{
		SerialNumber:      issued.SerialNumber,
		DeviceID:          req.DeviceID,
		TenantID:          req.TenantID,
		SubjectSummary:    issued.SubjectSummary,
		SANSummary:        issued.SANSummary,
		FingerprintSHA256: issued.FingerprintSHA256,
		Profile:           issued.Profile,
		IssuanceStatus:    issued.IssuanceStatus,
		IssuedAt:          issued.NotBefore,
		ExpiresAt:         issued.NotAfter,
		CreatedAt:         now,
		UpdatedAt:         now,
	}); err != nil {
		return nil, domain.NewAppError(
			"persistence_error",
			"failed to persist issuance record",
			fmt.Errorf("%w: %w", domain.ErrPersistence, err),
			nil,
		)
	}

	return issued, nil
}

func (s *CertificateIssuer) newCertificateTemplate(
	req domain.IssueRequest,
	validatedCSR *domain.ValidatedCSR,
	serialNumber *big.Int,
	notBefore time.Time,
	notAfter time.Time,
) *x509.Certificate {
	subject := pkix.Name{
		CommonName:         validatedCSR.Identity.CommonName,
		Organization:       []string{s.cfg.SubjectOrg},
		OrganizationalUnit: []string{s.cfg.SubjectOrgUnit},
		Country:            []string{s.cfg.SubjectCountry},
		Province:           []string{s.cfg.SubjectProvince},
		Locality:           []string{s.cfg.SubjectLocality},
	}
	if s.cfg.SubjectCommonName != "" {
		subject.SerialNumber = req.DeviceID
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:              validatedCSR.Identity.DNSNames,
	}

	for _, rawURI := range validatedCSR.Identity.URIs {
		uri, err := ParseURI(rawURI)
		if err == nil {
			template.URIs = append(template.URIs, uri)
		}
	}

	if _, ok := validatedCSR.PublicKey.(*rsa.PublicKey); ok {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	return template
}

package service

import (
	"crypto/x509"
	"net"
	"net/url"
	"strings"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/domain"
	"device-cert-issuer/internal/infra/pemutil"
)

type ServerCSRValidator struct {
	allowedKeyAlgorithms map[string]struct{}
	allowedCurves        map[string]struct{}
	allowedRSABits       map[int]struct{}
}

func NewServerCSRValidator(cfg config.IssuanceConfig) *ServerCSRValidator {
	keyAlgorithms := make(map[string]struct{}, len(cfg.AllowedKeyAlgos))
	for _, algo := range cfg.AllowedKeyAlgos {
		keyAlgorithms[strings.ToUpper(algo)] = struct{}{}
	}

	curves := make(map[string]struct{}, len(cfg.AllowedCurves))
	for _, curve := range cfg.AllowedCurves {
		curves[normalizeCurveName(curve)] = struct{}{}
	}

	rsaBits := make(map[int]struct{}, len(cfg.AllowedRSABits))
	for _, bits := range cfg.AllowedRSABits {
		rsaBits[bits] = struct{}{}
	}

	return &ServerCSRValidator{
		allowedKeyAlgorithms: keyAlgorithms,
		allowedCurves:        curves,
		allowedRSABits:       rsaBits,
	}
}

func (v *ServerCSRValidator) Validate(csrPEM string) (*domain.ValidatedCSR, error) {
	block, err := pemutil.DecodeSingleBlock([]byte(csrPEM), "CERTIFICATE REQUEST")
	if err != nil {
		return nil, domain.NewAppError("invalid_csr", "failed to parse CSR PEM", domain.ErrInvalidCSR, nil)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, domain.NewAppError("invalid_csr", "failed to parse CSR", domain.ErrInvalidCSR, nil)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, domain.NewAppError("invalid_csr", "CSR signature validation failed", domain.ErrInvalidCSR, nil)
	}
	if csr.PublicKey == nil {
		return nil, domain.NewAppError("invalid_csr", "CSR public key is missing", domain.ErrInvalidCSR, nil)
	}
	if err := validatePublicKeyPolicy(csr.PublicKey, v.allowedKeyAlgorithms, v.allowedCurves, v.allowedRSABits); err != nil {
		return nil, err
	}
	if err := validateNoCAIntent(csr); err != nil {
		return nil, err
	}

	dnsNames, ipAddresses, uriStrings, err := validateServerIdentities(csr)
	if err != nil {
		return nil, err
	}

	// 현대 TLS 검증은 CN 보다 SAN 을 기준으로 동작하므로 SAN 이 반드시 있어야 한다
	return &domain.ValidatedCSR{
		PublicKey: csr.PublicKey,
		Identity: domain.CSRIdentity{
			SubjectSummary: csr.Subject.String(),
			SANSummary:     buildSANSummary(dnsNames, parseIPStrings(ipAddresses), parseURIStrings(uriStrings)),
			CommonName:     strings.TrimSpace(csr.Subject.CommonName),
			DNSNames:       dnsNames,
			IPAddresses:    ipAddresses,
			URIs:           uriStrings,
		},
	}, nil
}

func validateNoCAIntent(csr *x509.CertificateRequest) error {
	for _, ext := range csr.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 19}) {
			return domain.NewAppError("policy_violation", "CA basic constraints are not allowed", domain.ErrPolicyViolation, nil)
		}
	}

	return nil
}

func validateServerIdentities(csr *x509.CertificateRequest) ([]string, []string, []string, error) {
	dnsNames := make([]string, 0, len(csr.DNSNames))
	for _, dnsName := range csr.DNSNames {
		trimmed := strings.TrimSpace(dnsName)
		if trimmed == "" || trimmed != dnsName || !isLikelyDNSName(trimmed) {
			return nil, nil, nil, domain.NewAppError("policy_violation", "CSR contains invalid DNS SAN", domain.ErrPolicyViolation, nil)
		}
		dnsNames = append(dnsNames, trimmed)
	}

	ipAddresses := make([]string, 0, len(csr.IPAddresses))
	for _, ipAddress := range csr.IPAddresses {
		if ipAddress == nil || ipAddress.String() == "<nil>" {
			return nil, nil, nil, domain.NewAppError("policy_violation", "CSR contains invalid IP SAN", domain.ErrPolicyViolation, nil)
		}
		ipAddresses = append(ipAddresses, ipAddress.String())
	}

	uriStrings := make([]string, 0, len(csr.URIs))
	for _, uri := range csr.URIs {
		if uri == nil || strings.TrimSpace(uri.Scheme) == "" {
			return nil, nil, nil, domain.NewAppError("policy_violation", "CSR contains invalid URI SAN", domain.ErrPolicyViolation, nil)
		}
		uriStrings = append(uriStrings, uri.String())
	}

	if len(dnsNames) == 0 && len(ipAddresses) == 0 && len(uriStrings) == 0 {
		return nil, nil, nil, domain.NewAppError("policy_violation", "CSR must contain at least one server SAN identity", domain.ErrPolicyViolation, nil)
	}

	return dnsNames, ipAddresses, uriStrings, nil
}

func isLikelyDNSName(v string) bool {
	if len(v) > 253 || strings.HasPrefix(v, ".") || strings.HasSuffix(v, ".") {
		return false
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}
		return false
	}

	return true
}

func parseIPStrings(values []string) []net.IP {
	result := make([]net.IP, 0, len(values))
	for _, value := range values {
		result = append(result, net.ParseIP(value))
	}

	return result
}

func parseURIStrings(values []string) []*url.URL {
	result := make([]*url.URL, 0, len(values))
	for _, value := range values {
		uri, err := url.Parse(value)
		if err == nil {
			result = append(result, uri)
		}
	}

	return result
}

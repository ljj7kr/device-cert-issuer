package service

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/domain"
	"device-cert-issuer/internal/infra/pemutil"
)

type CSRValidator struct {
	allowedKeyAlgorithms map[string]struct{}
	allowedCurves        map[string]struct{}
	allowedRSABits       map[int]struct{}
}

func NewCSRValidator(cfg config.IssuanceConfig) *CSRValidator {
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

	return &CSRValidator{
		allowedKeyAlgorithms: keyAlgorithms,
		allowedCurves:        curves,
		allowedRSABits:       rsaBits,
	}
}

func (v *CSRValidator) Validate(req domain.IssueRequest, enrollment *domain.EnrollmentRecord) (*domain.ValidatedCSR, error) {
	block, err := pemutil.DecodeSingleBlock([]byte(req.CSRPEM), "CERTIFICATE REQUEST")
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

	if len(csr.EmailAddresses) > 0 || len(csr.IPAddresses) > 0 {
		return nil, domain.NewAppError("policy_violation", "CSR contains forbidden SAN types", domain.ErrPolicyViolation, nil)
	}

	if len(csr.Extensions) > 0 {
		for _, ext := range csr.Extensions {
			if ext.Id.Equal([]int{2, 5, 29, 19}) {
				return nil, domain.NewAppError("policy_violation", "CA basic constraints are not allowed", domain.ErrPolicyViolation, nil)
			}
		}
	}

	if err := v.validateKey(csr.PublicKey); err != nil {
		return nil, err
	}

	if err := validateSubjectAndSAN(req, enrollment, csr); err != nil {
		return nil, err
	}

	return &domain.ValidatedCSR{
		PublicKey: csr.PublicKey,
		Identity: domain.CSRIdentity{
			SubjectSummary: csr.Subject.String(),
			SANSummary:     buildSANSummary(csr.DNSNames, csr.IPAddresses, csr.URIs),
			CommonName:     csr.Subject.CommonName,
			DNSNames:       csr.DNSNames,
			IPAddresses:    stringifyIPAddresses(csr.IPAddresses),
			URIs:           stringifyURIs(csr.URIs),
		},
	}, nil
}

func (v *CSRValidator) validateKey(publicKey any) error {
	return validatePublicKeyPolicy(publicKey, v.allowedKeyAlgorithms, v.allowedCurves, v.allowedRSABits)
}

func validatePublicKeyPolicy(publicKey any, allowedKeyAlgorithms map[string]struct{}, allowedCurves map[string]struct{}, allowedRSABits map[int]struct{}) error {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if _, ok := allowedKeyAlgorithms["RSA"]; !ok {
			return domain.NewAppError("policy_violation", "RSA keys are not allowed", domain.ErrPolicyViolation, nil)
		}
		if _, ok := allowedRSABits[key.Size()*8]; !ok {
			return domain.NewAppError("policy_violation", "RSA key size is not allowed", domain.ErrPolicyViolation, nil)
		}
	case *ecdsa.PublicKey:
		if _, ok := allowedKeyAlgorithms["ECDSA"]; !ok {
			return domain.NewAppError("policy_violation", "ECDSA keys are not allowed", domain.ErrPolicyViolation, nil)
		}
		if _, ok := allowedCurves[normalizeCurveName(key.Curve.Params().Name)]; !ok {
			return domain.NewAppError("policy_violation", "ECDSA curve is not allowed", domain.ErrPolicyViolation, nil)
		}
	case ed25519.PublicKey:
		if _, ok := allowedKeyAlgorithms["ED25519"]; !ok {
			return domain.NewAppError("policy_violation", "Ed25519 keys are not allowed", domain.ErrPolicyViolation, nil)
		}
		if _, ok := allowedCurves["ED25519"]; !ok {
			return domain.NewAppError("policy_violation", "Ed25519 is not allowed", domain.ErrPolicyViolation, nil)
		}
	default:
		return domain.NewAppError("policy_violation", "unsupported key algorithm", domain.ErrPolicyViolation, nil)
	}

	return nil
}

func validateSubjectAndSAN(req domain.IssueRequest, enrollment *domain.EnrollmentRecord, csr *x509.CertificateRequest) error {
	expectedCommonName := expectedCommonName(req)
	if csr.Subject.CommonName != expectedCommonName {
		return domain.NewAppError("policy_violation", "CSR common name does not match expected device identity", domain.ErrPolicyViolation, nil)
	}

	expectedURI := expectedDeviceURI(req)
	if len(csr.URIs) != 1 || csr.URIs[0].String() != expectedURI {
		return domain.NewAppError("policy_violation", "CSR URI SAN does not match expected device identity", domain.ErrPolicyViolation, nil)
	}

	expectedDNS := expectedDNSName(req)
	if len(csr.DNSNames) > 1 {
		return domain.NewAppError("policy_violation", "too many DNS SAN entries", domain.ErrPolicyViolation, nil)
	}
	if len(csr.DNSNames) == 1 && csr.DNSNames[0] != expectedDNS {
		return domain.NewAppError("policy_violation", "CSR DNS SAN does not match expected device identity", domain.ErrPolicyViolation, nil)
	}

	if enrollment != nil && enrollment.Model != req.Model {
		return domain.NewAppError("unauthorized_device", "device enrollment metadata mismatch", domain.ErrUnauthorizedDevice, nil)
	}

	return nil
}

func buildSANSummary(dnsNames []string, ipAddresses []net.IP, uris []*url.URL) string {
	uriValues := stringifyURIs(uris)
	ipValues := stringifyIPAddresses(ipAddresses)
	parts := make([]string, 0, len(dnsNames)+len(uriValues)+len(ipValues))
	for _, dnsName := range dnsNames {
		parts = append(parts, "DNS:"+dnsName)
	}
	for _, ipValue := range ipValues {
		parts = append(parts, "IP:"+ipValue)
	}
	for _, uriValue := range uriValues {
		parts = append(parts, "URI:"+uriValue)
	}

	return strings.Join(parts, ",")
}

func stringifyIPAddresses(ipAddresses []net.IP) []string {
	result := make([]string, 0, len(ipAddresses))
	for _, ipAddress := range ipAddresses {
		result = append(result, ipAddress.String())
	}

	return result
}

func stringifyURIs(uris []*url.URL) []string {
	result := make([]string, 0, len(uris))
	for _, uri := range uris {
		result = append(result, uri.String())
	}

	return result
}

func expectedCommonName(req domain.IssueRequest) string {
	return fmt.Sprintf("%s:%s", req.TenantID, req.DeviceID)
}

func expectedDNSName(req domain.IssueRequest) string {
	return fmt.Sprintf("%s.%s.devices.local", req.DeviceID, req.TenantID)
}

func expectedDeviceURI(req domain.IssueRequest) string {
	return fmt.Sprintf("spiffe://devices/%s/%s/%s", req.TenantID, req.Model, req.DeviceID)
}

func normalizeCurveName(v string) string {
	upper := strings.ToUpper(strings.TrimSpace(v))
	return strings.ReplaceAll(upper, "-", "")
}

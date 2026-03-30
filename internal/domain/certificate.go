package domain

import "time"

type IssueRequest struct {
	DeviceID string
	TenantID string
	Model    string
	CSRPEM   string
	Profile  string
}

type EnrollmentRecord struct {
	DeviceID       string
	TenantID       string
	Model          string
	AllowedProfile string
}

type CSRIdentity struct {
	SubjectSummary string
	SANSummary     string
	CommonName     string
	DNSNames       []string
	IPAddresses    []string
	URIs           []string
}

type ValidatedCSR struct {
	PublicKey any
	Identity  CSRIdentity
}

type IssuedCertificate struct {
	DeviceCertificatePEM string
	CertificateChainPEM  string
	SerialNumber         string
	NotBefore            time.Time
	NotAfter             time.Time
	FingerprintSHA256    string
	SubjectSummary       string
	SANSummary           string
	Profile              string
	IssuanceStatus       string
}

type IssueServerCertificateRequest struct {
	CSRPEM string
}

type IssuedServerCertificate struct {
	CertificatePEM    string
	ChainPEM          string
	FullChainPEM      string
	SerialNumber      string
	NotBefore         time.Time
	NotAfter          time.Time
	SubjectSummary    string
	SANSummary        string
	FingerprintSHA256 string
	Profile           string
	IssuanceStatus    string
}

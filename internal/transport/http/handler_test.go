package httptransport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"device-cert-issuer/internal/domain"
	httptransport "device-cert-issuer/internal/transport/http"
)

type issueServiceStub struct {
	issued *domain.IssuedCertificate
	err    error
}

func (s *issueServiceStub) Issue(context.Context, domain.IssueRequest, string) (*domain.IssuedCertificate, error) {
	return s.issued, s.err
}

type readinessServiceStub struct {
	status *domain.ReadinessStatus
	err    error
}

func (s *readinessServiceStub) Check(context.Context) (*domain.ReadinessStatus, error) {
	return s.status, s.err
}

func TestHandler_인증서를_발급한다(t *testing.T) {
	handler := httptransport.NewHTTPHandler(
		httptransport.NewHandler(
			&issueServiceStub{
				issued: &domain.IssuedCertificate{
					DeviceCertificatePEM: "device-cert",
					CertificateChainPEM:  "chain",
					SerialNumber:         "2A",
					NotBefore:            time.Unix(0, 0).UTC(),
					NotAfter:             time.Unix(3600, 0).UTC(),
				},
			},
			&readinessServiceStub{status: &domain.ReadinessStatus{Status: "ready"}},
		),
		4096,
	)

	body, err := json.Marshal(map[string]any{
		"device_id": "device-1",
		"tenant_id": "tenant-1",
		"model":     "model-a",
		"csr_pem":   "-----BEGIN CERTIFICATE REQUEST-----\nabc\n-----END CERTIFICATE REQUEST-----",
	})
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/device-certificates:issue", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestHandler_레디니스_실패를_반환한다(t *testing.T) {
	handler := httptransport.NewHTTPHandler(
		httptransport.NewHandler(
			&issueServiceStub{},
			&readinessServiceStub{err: domain.NewAppError("internal_error", "database is not ready", domain.ErrNotReady, nil)},
		),
		4096,
	)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestHandler_Swagger_UI를_제공한다(t *testing.T) {
	handler := httptransport.NewHTTPHandler(
		httptransport.NewHandler(
			&issueServiceStub{},
			&readinessServiceStub{status: &domain.ReadinessStatus{Status: "ready"}},
		),
		4096,
	)

	req := httptest.NewRequest(http.MethodGet, "/swagger", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("SwaggerUIBundle")) {
		t.Fatalf("expected swagger ui body, got %s", rec.Body.String())
	}
}

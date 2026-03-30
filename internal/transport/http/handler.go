package httptransport

import (
	"context"
	_ "embed"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"device-cert-issuer/internal/domain"
	"device-cert-issuer/internal/gen/openapi"
	"device-cert-issuer/internal/service"
)

//go:embed swagger.html
var swaggerHTML string

type IssueService interface {
	Issue(ctx context.Context, req domain.IssueRequest, requestID string) (*domain.IssuedCertificate, error)
}

type IssueServerService interface {
	Issue(ctx context.Context, req domain.IssueServerCertificateRequest, requestID string) (*domain.IssuedServerCertificate, error)
}

type ReadinessService interface {
	Check(ctx context.Context) (*domain.ReadinessStatus, error)
}

type Handler struct {
	issueService       IssueService
	serverIssueService IssueServerService
	readinessService   ReadinessService
}

func NewHandler(issueService IssueService, serverIssueService IssueServerService, readinessService ReadinessService) *Handler {
	return &Handler{
		issueService:       issueService,
		serverIssueService: serverIssueService,
		readinessService:   readinessService,
	}
}

func (h *Handler) GetHealthz(context.Context, openapi.GetHealthzRequestObject) (openapi.GetHealthzResponseObject, error) {
	return openapi.GetHealthz200JSONResponse{
		Status: "ok",
	}, nil
}

func (h *Handler) GetReadyz(ctx context.Context, _ openapi.GetReadyzRequestObject) (openapi.GetReadyzResponseObject, error) {
	status, err := h.readinessService.Check(ctx)
	if err != nil {
		return openapi.GetReadyz503JSONResponse(toErrorResponse(err, "")), nil
	}

	return openapi.GetReadyz200JSONResponse{
		Status: status.Status,
	}, nil
}

func (h *Handler) PostApiV1DeviceCertificatesIssue(ctx context.Context, request openapi.PostApiV1DeviceCertificatesIssueRequestObject) (openapi.PostApiV1DeviceCertificatesIssueResponseObject, error) {
	if request.Body == nil {
		return openapi.PostApiV1DeviceCertificatesIssue400JSONResponse{
			Code:    "invalid_request",
			Message: "request body is required",
		}, nil
	}

	requestID := RequestIDFromContext(ctx)
	req := domain.IssueRequest{
		DeviceID: strings.TrimSpace(request.Body.DeviceId),
		TenantID: strings.TrimSpace(request.Body.TenantId),
		Model:    strings.TrimSpace(request.Body.Model),
		CSRPEM:   strings.TrimSpace(request.Body.CsrPem),
	}
	if request.Body.Profile != nil {
		req.Profile = strings.TrimSpace(*request.Body.Profile)
	}

	issued, err := h.issueService.Issue(ctx, req, requestID)
	if err != nil {
		errorResponse := toErrorResponse(err, requestID)
		switch errorResponse.Code {
		case "invalid_request", "invalid_csr":
			return openapi.PostApiV1DeviceCertificatesIssue400JSONResponse(errorResponse), nil
		case "policy_violation", "unauthorized_device":
			return openapi.PostApiV1DeviceCertificatesIssue403JSONResponse(errorResponse), nil
		case "signer_unavailable":
			return openapi.PostApiV1DeviceCertificatesIssue503JSONResponse(errorResponse), nil
		default:
			return openapi.PostApiV1DeviceCertificatesIssue500JSONResponse(errorResponse), nil
		}
	}

	return openapi.PostApiV1DeviceCertificatesIssue200JSONResponse{
		DeviceCertificatePem: issued.DeviceCertificatePEM,
		CertificateChainPem:  issued.CertificateChainPEM,
		SerialNumber:         issued.SerialNumber,
		NotBefore:            issued.NotBefore,
		NotAfter:             issued.NotAfter,
	}, nil
}

func (h *Handler) PostApiV1ServerCertificatesIssue(ctx context.Context, request openapi.PostApiV1ServerCertificatesIssueRequestObject) (openapi.PostApiV1ServerCertificatesIssueResponseObject, error) {
	if request.Body == nil {
		return openapi.PostApiV1ServerCertificatesIssue400JSONResponse{
			Code:    "invalid_request",
			Message: "request body is required",
		}, nil
	}

	requestID := RequestIDFromContext(ctx)
	issued, err := h.serverIssueService.Issue(ctx, domain.IssueServerCertificateRequest{
		CSRPEM: strings.TrimSpace(request.Body.CsrPem),
	}, requestID)
	if err != nil {
		errorResponse := toErrorResponse(err, requestID)
		switch errorResponse.Code {
		case "invalid_request", "invalid_csr":
			return openapi.PostApiV1ServerCertificatesIssue400JSONResponse(errorResponse), nil
		case "policy_violation", "unauthorized_device":
			return openapi.PostApiV1ServerCertificatesIssue403JSONResponse(errorResponse), nil
		case "signer_unavailable":
			return openapi.PostApiV1ServerCertificatesIssue503JSONResponse(errorResponse), nil
		default:
			return openapi.PostApiV1ServerCertificatesIssue500JSONResponse(errorResponse), nil
		}
	}

	return openapi.PostApiV1ServerCertificatesIssue200JSONResponse{
		CertificatePem: issued.CertificatePEM,
		ChainPem:       issued.ChainPEM,
		FullchainPem:   issued.FullChainPEM,
		SerialNumber:   issued.SerialNumber,
		NotBefore:      issued.NotBefore,
		NotAfter:       issued.NotAfter,
		SubjectSummary: &issued.SubjectSummary,
		SanSummary:     &issued.SANSummary,
	}, nil
}

func toErrorResponse(err error, requestID string) openapi.ErrorResponse {
	appErr := service.AsAppError(err)
	response := openapi.ErrorResponse{
		Code:    appErr.Code,
		Message: appErr.Message,
	}
	response.Details = toErrorResponseDetails(appErr.Details)
	if requestID != "" {
		response.RequestId = &requestID
	}

	return response
}

func NewHTTPHandler(server openapi.StrictServerInterface, bodyLimit int64) http.Handler {
	strictHandler := openapi.NewStrictHandler(server, nil)
	apiHandler := withRequestID(withBodyLimit(openapi.Handler(strictHandler), bodyLimit))
	mux := http.NewServeMux()
	mux.HandleFunc("/swagger", serveSwaggerUI)
	mux.HandleFunc("/swagger/", serveSwaggerUI)
	mux.HandleFunc("/openapi.yaml", serveOpenAPISpec)
	mux.Handle("/", apiHandler)

	return mux
}

func toErrorResponseDetails(details any) *openapi.ErrorResponse_Details {
	if details == nil {
		return nil
	}

	var union openapi.ErrorResponse_Details

	switch value := details.(type) {
	case map[string]any:
		if err := union.FromErrorResponseDetails0(value); err == nil {
			return &union
		}
	case []map[string]string:
		items := make([]map[string]any, 0, len(value))
		for _, item := range value {
			converted := make(map[string]any, len(item))
			for key, itemValue := range item {
				converted[key] = itemValue
			}
			items = append(items, converted)
		}
		if err := union.FromErrorResponseDetails1(items); err == nil {
			return &union
		}
	case []map[string]any:
		if err := union.FromErrorResponseDetails1(value); err == nil {
			return &union
		}
	}

	return nil
}

func serveSwaggerUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerHTML))
}

func serveOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	specBytes, err := os.ReadFile(openAPISpecPath())
	if err != nil {
		http.Error(w, "failed to load openapi spec", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(specBytes)
}

func openAPISpecPath() string {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("api", "openapi.yaml")
	}

	return filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "api", "openapi.yaml")
}

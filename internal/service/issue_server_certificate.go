package service

import (
	"context"
	"log/slog"
	"strings"

	"device-cert-issuer/internal/domain"
)

type IssueServerCertificateService struct {
	logger                  *slog.Logger
	requestValidator        *ServerRequestValidator
	serverCSRValidator      *ServerCSRValidator
	serverCertificateIssuer *ServerCertificateIssuer
}

func NewIssueServerCertificateService(
	logger *slog.Logger,
	requestValidator *ServerRequestValidator,
	serverCSRValidator *ServerCSRValidator,
	serverCertificateIssuer *ServerCertificateIssuer,
) *IssueServerCertificateService {
	return &IssueServerCertificateService{
		logger:                  logger,
		requestValidator:        requestValidator,
		serverCSRValidator:      serverCSRValidator,
		serverCertificateIssuer: serverCertificateIssuer,
	}
}

func (s *IssueServerCertificateService) Issue(ctx context.Context, req domain.IssueServerCertificateRequest, requestID string) (*domain.IssuedServerCertificate, error) {
	s.logger.InfoContext(ctx, "server certificate issuance request received",
		slog.String("request_id", requestID),
	)

	req.CSRPEM = strings.TrimSpace(req.CSRPEM)
	validReq, err := s.requestValidator.Validate(req)
	if err != nil {
		s.logger.WarnContext(ctx, "server request validation failed",
			slog.String("request_id", requestID),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	validatedCSR, err := s.serverCSRValidator.Validate(validReq.CSRPEM)
	if err != nil {
		s.logger.WarnContext(ctx, "server CSR validation failed",
			slog.String("request_id", requestID),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	issued, err := s.serverCertificateIssuer.Issue(ctx, validatedCSR)
	if err != nil {
		logAttrs := []any{
			slog.String("request_id", requestID),
			slog.String("error", err.Error()),
		}
		if appErr := AsAppError(err); appErr != nil && appErr.Err != nil {
			logAttrs = append(logAttrs, slog.String("cause", appErr.Err.Error()))
		}

		s.logger.ErrorContext(ctx, "server certificate issuance failed", logAttrs...)
		return nil, err
	}

	s.logger.InfoContext(ctx, "server certificate issued successfully",
		slog.String("request_id", requestID),
		slog.String("serial_number", issued.SerialNumber),
	)

	return issued, nil
}

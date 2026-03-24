package service

import (
	"context"
	"fmt"
	"log/slog"

	"device-cert-issuer/internal/domain"
)

type IssueDeviceCertificateService struct {
	logger               *slog.Logger
	requestValidator     *RequestValidator
	enrollmentAuthorizer EnrollmentAuthorizer
	csrValidator         *CSRValidator
	certificateIssuer    *CertificateIssuer
}

func NewIssueDeviceCertificateService(
	logger *slog.Logger,
	requestValidator *RequestValidator,
	enrollmentAuthorizer EnrollmentAuthorizer,
	csrValidator *CSRValidator,
	certificateIssuer *CertificateIssuer,
) *IssueDeviceCertificateService {
	return &IssueDeviceCertificateService{
		logger:               logger,
		requestValidator:     requestValidator,
		enrollmentAuthorizer: enrollmentAuthorizer,
		csrValidator:         csrValidator,
		certificateIssuer:    certificateIssuer,
	}
}

func (s *IssueDeviceCertificateService) Issue(ctx context.Context, req domain.IssueRequest, requestID string) (*domain.IssuedCertificate, error) {
	s.logger.InfoContext(ctx, "certificate issuance request received",
		slog.String("request_id", requestID),
		slog.String("device_id", req.DeviceID),
		slog.String("tenant_id", req.TenantID),
		slog.String("profile", req.Profile),
	)

	validReq, err := s.requestValidator.Validate(req)
	if err != nil {
		s.logger.WarnContext(ctx, "request validation failed",
			slog.String("request_id", requestID),
			slog.String("device_id", req.DeviceID),
			slog.String("tenant_id", req.TenantID),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	enrollment, err := s.enrollmentAuthorizer.Authorize(ctx, validReq)
	if err != nil {
		s.logger.WarnContext(ctx, "device enrollment rejected",
			slog.String("request_id", requestID),
			slog.String("device_id", req.DeviceID),
			slog.String("tenant_id", req.TenantID),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	validatedCSR, err := s.csrValidator.Validate(validReq, enrollment)
	if err != nil {
		s.logger.WarnContext(ctx, "CSR validation failed",
			slog.String("request_id", requestID),
			slog.String("device_id", req.DeviceID),
			slog.String("tenant_id", req.TenantID),
			slog.String("error", err.Error()),
		)
		return nil, err
	}

	issued, err := s.certificateIssuer.Issue(ctx, validReq, validatedCSR)
	if err != nil {
		logAttrs := []any{
			slog.String("request_id", requestID),
			slog.String("device_id", req.DeviceID),
			slog.String("tenant_id", req.TenantID),
			slog.String("error", err.Error()),
		}
		if appErr := AsAppError(err); appErr != nil && appErr.Err != nil {
			logAttrs = append(logAttrs, slog.String("cause", appErr.Err.Error()))
		}

		s.logger.ErrorContext(ctx, "certificate issuance failed", logAttrs...)
		return nil, err
	}

	s.logger.InfoContext(ctx, "certificate issued successfully",
		slog.String("request_id", requestID),
		slog.String("device_id", req.DeviceID),
		slog.String("tenant_id", req.TenantID),
		slog.String("serial_number", issued.SerialNumber),
	)

	return issued, nil
}

func AsAppError(err error) *domain.AppError {
	if err == nil {
		return nil
	}

	var appErr *domain.AppError
	if ok := As(err, &appErr); ok {
		return appErr
	}

	return domain.NewAppError("internal_error", "internal server error", domain.ErrInternal, []map[string]string{{"reason": fmt.Sprint(err)}})
}

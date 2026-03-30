package app

import (
	"database/sql"
	"fmt"
	"log/slog"

	"device-cert-issuer/internal/config"
	"device-cert-issuer/internal/gen/openapi"
	"device-cert-issuer/internal/gen/sqlc"
	"device-cert-issuer/internal/infra/clock"
	"device-cert-issuer/internal/infra/serial"
	"device-cert-issuer/internal/infra/signer"
	"device-cert-issuer/internal/repository/mysql"
	"device-cert-issuer/internal/service"
	httptransport "device-cert-issuer/internal/transport/http"
)

type App struct {
	Handler httptransport.Handler
}

func New(
	cfg config.Config,
	logger *slog.Logger,
	db *sql.DB,
	certificateSigner signer.CertificateSigner,
) (*httptransport.Handler, error) {
	if certificateSigner == nil {
		return nil, fmt.Errorf("certificate signer is required")
	}

	queries := sqlc.New(db)
	deviceCertificateRepository := mysql.NewDeviceCertificateRepository(queries)
	requestValidator := service.NewRequestValidator(cfg.Issuance)
	serverRequestValidator := service.NewServerRequestValidator()
	enrollmentAuthorizer := service.NewStaticEnrollmentAuthorizer()
	csrValidator := service.NewCSRValidator(cfg.Issuance)
	serverCSRValidator := service.NewServerCSRValidator(cfg.Issuance)
	certificateIssuer := service.NewCertificateIssuer(
		cfg.Issuance,
		clock.SystemClock{},
		serial.RandomGenerator{},
		certificateSigner,
		deviceCertificateRepository,
	)
	serverCertificateIssuer := service.NewServerCertificateIssuer(
		cfg.Issuance,
		clock.SystemClock{},
		serial.RandomGenerator{},
		certificateSigner,
		deviceCertificateRepository,
	)
	issueService := service.NewIssueDeviceCertificateService(
		logger,
		requestValidator,
		enrollmentAuthorizer,
		csrValidator,
		certificateIssuer,
	)
	issueServerService := service.NewIssueServerCertificateService(
		logger,
		serverRequestValidator,
		serverCSRValidator,
		serverCertificateIssuer,
	)
	readinessService := service.NewReadinessService(certificateSigner, db)
	handler := httptransport.NewHandler(issueService, issueServerService, readinessService)

	return handler, nil
}

var _ openapi.StrictServerInterface = (*httptransport.Handler)(nil)

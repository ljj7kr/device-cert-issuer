package service

import (
	"device-cert-issuer/internal/domain"

	"github.com/go-playground/validator/v10"
)

type serverRequestValidatorInput struct {
	CSRPEM string `validate:"required,max=16384"`
}

type ServerRequestValidator struct {
	validate *validator.Validate
}

func NewServerRequestValidator() *ServerRequestValidator {
	return &ServerRequestValidator{
		validate: validator.New(validator.WithRequiredStructEnabled()),
	}
}

func (v *ServerRequestValidator) Validate(req domain.IssueServerCertificateRequest) (domain.IssueServerCertificateRequest, error) {
	if err := v.validate.Struct(serverRequestValidatorInput{CSRPEM: req.CSRPEM}); err != nil {
		return domain.IssueServerCertificateRequest{}, domain.NewAppError("invalid_request", "request validation failed", domain.ErrInvalidRequest, []map[string]string{{"reason": err.Error()}})
	}

	return req, nil
}

package domain

import "errors"

var (
	ErrInvalidRequest     = errors.New("invalid_request")
	ErrInvalidCSR         = errors.New("invalid_csr")
	ErrPolicyViolation    = errors.New("policy_violation")
	ErrUnauthorizedDevice = errors.New("unauthorized_device")
	ErrSignerUnavailable  = errors.New("signer_unavailable")
	ErrPersistence        = errors.New("persistence_error")
	ErrInternal           = errors.New("internal_error")
	ErrNotReady           = errors.New("not_ready")
)

type AppError struct {
	Code    string
	Message string
	Details any
	Err     error
}

func (e *AppError) Error() string {
	if e == nil {
		return ""
	}

	return e.Code + ": " + e.Message
}

func (e *AppError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

func NewAppError(code string, message string, err error, details any) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Details: details,
		Err:     err,
	}
}

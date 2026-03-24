package pemutil

import (
	"encoding/pem"
	"errors"
	"fmt"
)

func DecodeSingleBlock(data []byte, expectedType string) (*pem.Block, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM block not found")
	}

	if len(rest) > 0 && len(trimSpace(rest)) > 0 {
		return nil, errors.New("unexpected trailing PEM data")
	}

	if expectedType != "" && block.Type != expectedType {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	return block, nil
}

func EncodeCertificateDER(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}))
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && isSpace(b[start]) {
		start++
	}

	end := len(b)
	for end > start && isSpace(b[end-1]) {
		end--
	}

	return b[start:end]
}

func isSpace(v byte) bool {
	switch v {
	case ' ', '\n', '\t', '\r':
		return true
	default:
		return false
	}
}

package serial

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type Generator interface {
	NewSerialNumber() (*big.Int, string, error)
}

type RandomGenerator struct{}

func (RandomGenerator) NewSerialNumber() (*big.Int, string, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, "", fmt.Errorf("generate serial number: %w", err)
	}

	if n.Sign() == 0 {
		n = big.NewInt(1)
	}

	return n, fmt.Sprintf("%X", n), nil
}

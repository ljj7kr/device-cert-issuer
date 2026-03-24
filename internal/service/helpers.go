package service

import (
	"context"
	"crypto/rand"
	"io"
	"net/url"
)

func ctxAwareRandomReader(_ context.Context) io.Reader {
	return rand.Reader
}

func ParseURI(raw string) (*url.URL, error) {
	return url.Parse(raw)
}

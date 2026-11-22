// SPDX-License-Identifier: GPL-3.0-only

// Package certificate validates operator-provided TLS material before any
// remote mutation. Private key bytes are never formatted into errors.
package certificate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Pair struct {
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Leaf           *x509.Certificate
}

func protectedRegularFile(path string, private bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("TLS material must be a regular file, not a symbolic link")
	}
	if private && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("TLS private key permissions must not allow group or other access")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func parsePrivateKey(raw []byte) (crypto.PrivateKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("private key must contain exactly one PEM block")
	}
	if x509.IsEncryptedPEMBlock(block) {
		return nil, errors.New("encrypted private keys are not supported in non-interactive deploy")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported or invalid TLS private key")
}

func publicKey(key crypto.PrivateKey) (crypto.PublicKey, error) {
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		return &typed.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &typed.PublicKey, nil
	case interface{ Public() crypto.PublicKey }:
		return typed.Public(), nil
	default:
		return nil, errors.New("TLS private key does not expose a public key")
	}
}

func validate(certRaw, keyRaw []byte, expectedName string, roots *x509.CertPool, now time.Time) (Pair, error) {
	if strings.TrimSpace(expectedName) == "" {
		return Pair{}, errors.New("expected TLS DNS name or IP is required")
	}
	var certificates []*x509.Certificate
	rest := certRaw
	for len(bytes.TrimSpace(rest)) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return Pair{}, errors.New("certificate file contains invalid PEM data")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return Pair{}, fmt.Errorf("parse TLS certificate: %w", err)
		}
		certificates = append(certificates, certificate)
		rest = next
	}
	if len(certificates) == 0 {
		return Pair{}, errors.New("certificate file contains no certificates")
	}
	leaf := certificates[0]
	if err := leaf.VerifyHostname(expectedName); err != nil {
		return Pair{}, fmt.Errorf("certificate does not cover %q: %w", expectedName, err)
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return Pair{}, errors.New("certificate is not currently valid")
	}
	if leaf.NotAfter.Sub(now) < 24*time.Hour {
		return Pair{}, errors.New("certificate expires in less than 24 hours")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	if roots == nil {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return Pair{}, fmt.Errorf("load system certificate roots: %w", err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: expectedName, Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return Pair{}, fmt.Errorf("certificate chain is not trusted: %w", err)
	}
	privateKey, err := parsePrivateKey(keyRaw)
	if err != nil {
		return Pair{}, err
	}
	keyPublic, err := publicKey(privateKey)
	if err != nil {
		return Pair{}, err
	}
	certPublic, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return Pair{}, err
	}
	keyPublicRaw, err := x509.MarshalPKIXPublicKey(keyPublic)
	if err != nil {
		return Pair{}, err
	}
	if !bytes.Equal(certPublic, keyPublicRaw) {
		return Pair{}, errors.New("TLS certificate and private key do not match")
	}
	return Pair{CertificatePEM: certRaw, PrivateKeyPEM: keyRaw, Leaf: leaf}, nil
}

// LoadExisting validates a publicly trusted server certificate and its private
// key against a DNS name or IP using the operator system trust store.
func LoadExisting(certPath, keyPath, expectedName string, now time.Time) (Pair, error) {
	certRaw, err := protectedRegularFile(certPath, false)
	if err != nil {
		return Pair{}, fmt.Errorf("read TLS certificate: %w", err)
	}
	keyRaw, err := protectedRegularFile(keyPath, true)
	if err != nil {
		return Pair{}, fmt.Errorf("read TLS private key: %w", err)
	}
	return validate(certRaw, keyRaw, expectedName, nil, now)
}

// SPDX-License-Identifier: GPL-3.0-only

package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makePair(t *testing.T, name string, now time.Time) ([]byte, []byte, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(36 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	if ip := net.ParseIP(name); ip != nil {
		leafTemplate.IPAddresses = []net.IP{ip}
	} else {
		leafTemplate.DNSNames = []string{name}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return certPEM, keyPEM, roots
}

func TestValidateTrustedMatchingPair(t *testing.T) {
	now := time.Unix(1800000000, 0)
	certPEM, keyPEM, roots := makePair(t, "subscription.example.test", now)
	pair, err := validate(certPEM, keyPEM, "subscription.example.test", roots, now)
	if err != nil {
		t.Fatal(err)
	}
	if pair.Leaf == nil || len(pair.PrivateKeyPEM) == 0 {
		t.Fatal("validated pair is incomplete")
	}
}

func TestValidateRejectsWrongNameAndKey(t *testing.T) {
	now := time.Unix(1800000000, 0)
	certPEM, keyPEM, roots := makePair(t, "subscription.example.test", now)
	if _, err := validate(certPEM, keyPEM, "wrong.example.test", roots, now); err == nil {
		t.Fatal("wrong DNS name was accepted")
	}
	_, otherKey, _ := makePair(t, "subscription.example.test", now)
	if _, err := validate(certPEM, otherKey, "subscription.example.test", roots, now); err == nil {
		t.Fatal("mismatched private key was accepted")
	}
}

func TestLoadRejectsLoosePrivateKeyPermissions(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, _ := makePair(t, "subscription.example.test", now)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExisting(certPath, keyPath, "subscription.example.test", now); err == nil {
		t.Fatal("world-readable private key was accepted")
	}
}

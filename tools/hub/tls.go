package hub

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// The hub proves who it is with the shared secret: its TLS key is derived
// from it. A hub known only by an internal DNS name (fw0's split-horizon
// zone) cannot get a publicly trusted certificate, and every machine that
// talks to the hub already holds the secret, so no CA, certificate file or
// public DNS record is needed. Anyone holding the secret could pose as the
// hub, but they could already drive every agent.

const tlsKeyInfo = "mpemu hub tls v1"

func derivedKey(secret string) (ed25519.PrivateKey, error) {
	if secret == "" {
		return nil, errors.New("hub tls: no secret to derive the key from")
	}
	seed, err := hkdf.Key(sha256.New, []byte(secret), nil, tlsKeyInfo, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ServerTLS is the hub's TLS configuration: a self-signed certificate over
// the secret-derived key.
func ServerTLS(secret string) (*tls.Config, error) {
	key, err := derivedKey(secret)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "mpemu hub"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("hub tls: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLS accepts a hub that presents the secret-derived key, or else a
// certificate the system trusts for the host name (a hub behind a real
// certificate or a TLS proxy).
func ClientTLS(secret string) *tls.Config {
	var want ed25519.PublicKey
	if key, err := derivedKey(secret); err == nil {
		want = key.Public().(ed25519.PublicKey)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Standard verification would reject the self-signed certificate
		// before the key could be compared; VerifyConnection does both.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("hub presented no certificate")
			}
			leaf := cs.PeerCertificates[0]
			if pub, ok := leaf.PublicKey.(ed25519.PublicKey); ok && want != nil && pub.Equal(want) {
				return nil
			}
			opts := x509.VerifyOptions{DNSName: cs.ServerName, Intermediates: x509.NewCertPool()}
			for _, c := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(c)
			}
			if _, err := leaf.Verify(opts); err != nil {
				return fmt.Errorf("hub certificate is neither derived from the shared secret nor trusted: %w", err)
			}
			return nil
		},
	}
}

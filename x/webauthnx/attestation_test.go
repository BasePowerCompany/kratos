// Copyright © 2026 Base Power Company
// SPDX-License-Identifier: Apache-2.0

package webauthnx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/text"
)

// yubiKeyU2FResponse is a registration by a real YubiKey, with fido-u2f
// attestation, from go-webauthn's protocol tests.
const yubiKeyU2FResponse = `{
"rawId": "7nJsttr4dLSsmrWnaHB3espJ0ua9rsJ2ws-93BFcNOP64g_s_4wLFDvklrNYcg0BCN6ddUjJLxDfDSBreKQLAw",
"id": "7nJsttr4dLSsmrWnaHB3espJ0ua9rsJ2ws-93BFcNOP64g_s_4wLFDvklrNYcg0BCN6ddUjJLxDfDSBreKQLAw",
"response": {
"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJhTDJ1d0FwZ3d1bUJ6VFlDY29MMF80RFJ2X21mWXlremdxSkJGb0pqX1dDS05aT3B2VVFueWpkd01XSVdLY1k4NDR0eUROTE81cFFQQk1KckhQel8zZyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQ0MzI5IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
"attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgRMxowC__Z-mgVR6netL6C7Q15weqiTCPwwq1EaeJVqMCIQCHb9cCad1VloGhQ60mw7KTJhkx61mfgKKwHUVZf1wR6mN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQO5ybLba-HS0rJq1p2hwd3rKSdLmva7CdsLPvdwRXDTj-uIP7P-MCxQ75JazWHINAQjenXVIyS8Q3w0ga3ikCwOlAQIDJiABIVggUOAo5xqsJoPfJWsU50h7c2S7_llP0KwGI6vJkEj1N48iWCA2TMSeBfhJ84HyMQQgjJvBiA6JnHA0chxSlmuZeT9Xgg"
},
"type": "public-key"
}`

// yubicoU2FRoot is "Yubico U2F Root CA Serial 457200631", from
// https://developers.yubico.com/PKI/yubico-ca-certs.txt.
const yubicoU2FRoot = `-----BEGIN CERTIFICATE-----
MIIDHjCCAgagAwIBAgIEG0BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290
IENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk
5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep
8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw
nebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT
9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw
LvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ
hjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN
BgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4
MYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt
hX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k
LVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U
sG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc
U9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==
-----END CERTIFICATE-----


Name: Yubico PIV Root CA Serial 263751
Issued: 2016-03-14
Address: https://developers.yubico.com/PKI/yubico-piv-ca-1.pem
         https://developers.yubico.com/PKI/yubico-piv-ca-1.pem.sig`

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// newCert issues a certificate for name, signed by parent, or self-signed
// when parent is nil.
func newCert(t *testing.T, name string, parent *testCA, isCA bool) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{cert: cert, key: key}
}

func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

func packed(certs ...*testCA) protocol.AttestationObject {
	x5c := make([]any, len(certs))
	for i, c := range certs {
		x5c[i] = c.cert.Raw
	}
	return protocol.AttestationObject{Format: "packed", AttStatement: map[string]any{"alg": int64(-7), "x5c": x5c}}
}

func TestVerifyHardwareKeyAttestation(t *testing.T) {
	yubico := x509.NewCertPool()
	require.True(t, yubico.AppendCertsFromPEM([]byte(yubicoU2FRoot)))
	parsed, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(yubiKeyU2FResponse))
	require.NoError(t, err)
	yubiKey := parsed.Response.AttestationObject

	root := newCert(t, "Vendor Root", nil, true)
	intermediate := newCert(t, "Vendor Intermediate", root, true)
	leaf := newCert(t, "Vendor Key", intermediate, false)
	selfSigned := newCert(t, "Software Authenticator", nil, false)

	for _, tc := range []struct {
		name    string
		att     protocol.AttestationObject
		anchors *x509.CertPool
		trusted bool
	}{
		{name: "a YubiKey chains to Yubico's root", att: yubiKey, anchors: yubico, trusted: true},
		{name: "a YubiKey is refused when only another vendor is trusted", att: yubiKey, anchors: pool(root.cert)},
		{name: "an intermediate the attestation carries completes the chain", att: packed(leaf, intermediate), anchors: pool(root.cert), trusted: true},
		{name: "a trusted intermediate is an anchor of its own", att: packed(leaf), anchors: pool(intermediate.cert), trusted: true},
		{name: "a leaf without its intermediate does not reach the root", att: packed(leaf), anchors: pool(root.cert)},
		{name: "a self-signed attestation certificate is refused", att: packed(selfSigned), anchors: yubico},
		{name: "self attestation, with no certificate, is refused", att: protocol.AttestationObject{Format: "packed", AttStatement: map[string]any{"alg": int64(-7)}}, anchors: yubico},
		{name: "no attestation, as a synced passkey sends, is refused", att: protocol.AttestationObject{Format: "none"}, anchors: yubico},
		{name: "an empty pool, from anchors that did not parse, refuses everything", att: yubiKey, anchors: x509.NewCertPool()},
	} {
		t.Run("case="+tc.name, func(t *testing.T) {
			err := VerifyHardwareKeyAttestation(tc.att, tc.anchors)
			if tc.trusted {
				require.NoError(t, err)
				return
			}
			var verr *schema.ValidationError
			require.True(t, errors.As(err, &verr), "%+v", err)
			require.Len(t, verr.Messages, 1)
			assert.Equal(t, text.ErrorValidationGeneric, verr.Messages[0].ID)
		})
	}
}

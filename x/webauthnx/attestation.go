// Copyright © 2026 Base Power Company
// SPDX-License-Identifier: Apache-2.0

package webauthnx

import (
	"crypto/x509"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pkg/errors"

	"github.com/ory/jsonschema/v3"
	"github.com/ory/kratos/schema"
	"github.com/ory/kratos/text"
)

// HardwareKeyRegistrationOptions asks the browser to go straight to a security
// key when anchors restrict which authenticators may be added.
func HardwareKeyRegistrationOptions(anchors *x509.CertPool) []webauthn.RegistrationOption {
	if anchors == nil {
		return nil
	}
	return []webauthn.RegistrationOption{
		webauthn.WithPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{protocol.PublicKeyCredentialHintSecurityKey}),
	}
}

// VerifyHardwareKeyAttestation refuses a new credential unless its attestation
// certificate chains to one of anchors.
//
// CreateCredential has already checked that the attestation's leaf
// certificate signed it, but not who issued that certificate, so a software
// authenticator could sign with a certificate of its own making. A synced
// passkey, which sends no attestation even when asked, is refused here too.
func VerifyHardwareKeyAttestation(att protocol.AttestationObject, anchors *x509.CertPool) error {
	if err := verifyAttestationChain(att, anchors); err != nil {
		return errors.WithStack(&schema.ValidationError{
			ValidationError: &jsonschema.ValidationError{
				Message:     fmt.Sprintf("security key attestation is not trusted: %s", err),
				InstancePtr: "#/webauthn_register",
			},
			Messages: new(text.Messages).Add(text.NewValidationErrorGeneric(
				"This key cannot be added. Only approved physical keys are accepted. If your browser asks whether to share your key's make and model, allow it.")),
		})
	}
	return nil
}

func verifyAttestationChain(att protocol.AttestationObject, anchors *x509.CertPool) error {
	x5c, _ := att.AttStatement["x5c"].([]any)
	if len(x5c) == 0 {
		return errors.Errorf("attestation format %q carries no certificate", att.Format)
	}
	chain := make([]*x509.Certificate, 0, len(x5c))
	for _, raw := range x5c {
		der, ok := raw.([]byte)
		if !ok {
			return errors.New("attestation certificate is not DER bytes")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return errors.Wrap(err, "parse attestation certificate")
		}
		chain = append(chain, cert)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         anchors,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return errors.WithStack(err)
}

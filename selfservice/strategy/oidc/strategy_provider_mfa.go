// Copyright © 2026 Base Power Company
// SPDX-License-Identifier: Apache-2.0

package oidc

import "slices"

// providerAssertedMFA reports whether a provider trusted with trust_amr_mfa
// asserted `mfa` (RFC 8176) in the verified ID token's amr claim.
func providerAssertedMFA(config *Configuration, claims *Claims) bool {
	if config == nil || !config.TrustAMRMFA || claims == nil {
		return false
	}
	amr, _ := claims.RawClaims["amr"].([]any)
	return slices.Contains(amr, any("mfa"))
}

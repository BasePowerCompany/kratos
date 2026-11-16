// Copyright © 2026 Base Power Company
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProviderAssertedMFA(t *testing.T) {
	trusted := &Configuration{TrustAMRMFA: true}
	withAMR := func(amr any) *Claims { return &Claims{RawClaims: map[string]any{"amr": amr}} }

	for _, tc := range []struct {
		name   string
		config *Configuration
		claims *Claims
		want   bool
	}{
		{"trusts mfa from a trusted provider", trusted, withAMR([]any{"pwd", "mfa"}), true},
		{"ignores mfa from an untrusted provider", &Configuration{}, withAMR([]any{"pwd", "mfa"}), false},
		{"needs mfa itself, not another method", trusted, withAMR([]any{"pwd", "otp"}), false},
		{"ignores a missing amr", trusted, &Claims{RawClaims: map[string]any{}}, false},
		{"ignores an amr that is not an array", trusted, withAMR("mfa"), false},
		{"ignores no claims", trusted, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, providerAssertedMFA(tc.config, tc.claims))
		})
	}
}

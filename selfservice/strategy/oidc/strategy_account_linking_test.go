// Copyright © 2026 Base Power Company
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ory/kratos/identity"
)

func TestAutomaticAccountLinking(t *testing.T) {
	withAddress := func(value string, verified bool) *identity.Identity {
		i := identity.NewIdentity("default")
		i.VerifiableAddresses = []identity.VerifiableAddress{{Value: value, Via: identity.AddressTypeEmail, Verified: verified}}
		return i
	}
	automatic := &Configuration{AccountLinkingMode: AccountLinkingModeAutomatic, AccountLinkingDomains: []string{"acme.example"}}

	for _, tc := range []struct {
		name     string
		config   *Configuration
		existing *identity.Identity
		incoming *identity.Identity
		want     ConflictingIdentityVerdict
	}{
		{"merges a verified address at a linking domain", automatic,
			withAddress("ada@acme.example", true), withAddress("Ada@ACME.example", true), ConflictingIdentityVerdictMerge},
		{"rejects without automatic mode", &Configuration{AccountLinkingDomains: []string{"acme.example"}},
			withAddress("ada@acme.example", true), withAddress("ada@acme.example", true), ConflictingIdentityVerdictReject},
		{"rejects an address outside the provider's domains", automatic,
			withAddress("ada@gmail.example", true), withAddress("ada@gmail.example", true), ConflictingIdentityVerdictReject},
		{"rejects a provider with no domains", &Configuration{AccountLinkingMode: AccountLinkingModeAutomatic},
			withAddress("ada@acme.example", true), withAddress("ada@acme.example", true), ConflictingIdentityVerdictReject},
		{"rejects an address the provider doesn't verify", automatic,
			withAddress("ada@acme.example", true), withAddress("ada@acme.example", false), ConflictingIdentityVerdictReject},
		{"rejects an existing identity that never verified it", automatic,
			withAddress("ada@acme.example", false), withAddress("ada@acme.example", true), ConflictingIdentityVerdictReject},
		{"rejects a different address", automatic,
			withAddress("bob@acme.example", true), withAddress("ada@acme.example", true), ConflictingIdentityVerdictReject},
		{"rejects no existing identity", automatic,
			nil, withAddress("ada@acme.example", true), ConflictingIdentityVerdictReject},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, automaticAccountLinking(tc.config, tc.existing, tc.incoming))
		})
	}
}

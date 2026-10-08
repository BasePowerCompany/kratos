// Copyright © 2026 Base Power Company
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"slices"
	"strings"

	"github.com/ory/kratos/identity"
)

// automaticAccountLinkingPolicy is the default ConflictingIdentityPolicy: it
// decides from the provider's own configuration.
func automaticAccountLinkingPolicy(_ context.Context, existing, incoming *identity.Identity, provider Provider, _ *Claims) ConflictingIdentityVerdict {
	return automaticAccountLinking(provider.Config(), existing, incoming)
}

// automaticAccountLinking merges when the provider is configured with
// account_linking_mode "automatic" and an address both identities have
// verified -- the provider asserting it now, the existing identity having
// proven it before -- is at one of the provider's account_linking_domains.
// A provider with no domains links none: it must be authoritative for an
// address's domain to claim the account behind it.
func automaticAccountLinking(config *Configuration, existing, incoming *identity.Identity) ConflictingIdentityVerdict {
	if config == nil || existing == nil || incoming == nil || config.AccountLinkingMode != AccountLinkingModeAutomatic {
		return ConflictingIdentityVerdictReject
	}
	for _, claimed := range incoming.VerifiableAddresses {
		if !claimed.Verified || !inDomains(claimed.Value, config.AccountLinkingDomains) {
			continue
		}
		for _, held := range existing.VerifiableAddresses {
			if held.Verified && held.Via == claimed.Via && strings.EqualFold(held.Value, claimed.Value) {
				return ConflictingIdentityVerdictMerge
			}
		}
	}
	return ConflictingIdentityVerdictReject
}

func inDomains(address string, domains []string) bool {
	at := strings.LastIndex(address, "@")
	if at < 0 {
		return false
	}
	domain := address[at+1:]
	return slices.ContainsFunc(domains, func(d string) bool { return strings.EqualFold(d, domain) })
}

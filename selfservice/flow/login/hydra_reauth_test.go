// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	hydraclientgo "github.com/ory/hydra-client-go/v2"

	"github.com/ory/kratos/session"
)

func TestHydraRequiresReauthentication(t *testing.T) {
	now := time.Now()
	active := &session.Session{
		Active:          true,
		AuthenticatedAt: now.Add(-10 * time.Minute),
		ExpiresAt:       now.Add(time.Hour),
	}
	const authorize = "https://hydra.example.com/oauth2/auth?client_id=app&response_type=code"

	for _, tc := range []struct {
		name       string
		requestURL string
		sess       *session.Session
		want       bool
	}{
		{name: "no session", requestURL: authorize, sess: nil, want: true},
		{name: "expired session", requestURL: authorize, sess: &session.Session{Active: true, ExpiresAt: now.Add(-time.Hour)}, want: true},
		{name: "session and nothing asked", requestURL: authorize, sess: active, want: false},
		{name: "prompt=login", requestURL: authorize + "&prompt=login", sess: active, want: true},
		{name: "prompt among several values", requestURL: authorize + "&prompt=consent+login", sess: active, want: true},
		{name: "prompt=consent alone", requestURL: authorize + "&prompt=consent", sess: active, want: false},
		{name: "max_age older than session", requestURL: authorize + "&max_age=3600", sess: active, want: false},
		{name: "max_age exceeded", requestURL: authorize + "&max_age=60", sess: active, want: true},
		{name: "max_age=0", requestURL: authorize + "&max_age=0", sess: active, want: true},
		{name: "unparseable max_age", requestURL: authorize + "&max_age=soon", sess: active, want: true},
		{name: "authorization parameters not in the URL", requestURL: "https://hydra.example.com/oauth2/auth", sess: active, want: true},
		{name: "unparseable URL", requestURL: "://", sess: active, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &hydraclientgo.OAuth2LoginRequest{RequestUrl: tc.requestURL}
			assert.Equal(t, tc.want, hydraRequiresReauthentication(req, tc.sess, now))
		})
	}
}

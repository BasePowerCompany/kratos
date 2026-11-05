// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package login

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	hydraclientgo "github.com/ory/hydra-client-go/v2"

	"github.com/ory/kratos/session"
)

// hydraRequiresReauthentication reports whether an OAuth2 login request that Hydra did not skip actually asks the
// user to authenticate again. Hydra also declines to skip when it merely holds no remembered login of its own, and an
// active Kratos session answers that case without a refresh.
//
// prompt and max_age are read from the authorization URL Hydra recorded. A request whose URL does not carry the
// authorization parameters (a POSTed authorization request) cannot be inspected, so it is treated as asking.
func hydraRequiresReauthentication(req *hydraclientgo.OAuth2LoginRequest, sess *session.Session, now time.Time) bool {
	if sess == nil || !sess.IsActive() {
		return true
	}
	u, err := url.Parse(req.GetRequestUrl())
	if err != nil {
		return true
	}
	q := u.Query()
	if !q.Has("client_id") {
		return true
	}
	if slices.Contains(strings.Fields(q.Get("prompt")), "login") {
		return true
	}
	if !q.Has("max_age") {
		return false
	}
	maxAge, err := strconv.ParseInt(q.Get("max_age"), 10, 64)
	if err != nil || maxAge <= 0 {
		return true
	}
	return now.Sub(sess.AuthenticatedAt) > time.Duration(maxAge)*time.Second
}

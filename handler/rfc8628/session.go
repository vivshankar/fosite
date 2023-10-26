// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// Session is required to support Device Authorization Grant flow
type Session interface {
	fosite.Session
}

var (
	_ Session = (*DefaultSession)(nil)
)

type DefaultSession struct {
	*openid.DefaultSession
}

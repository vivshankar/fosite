// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/rfc8628"
)

// RFC8628DeviceAuthorizationFactory creates an OAuth2 device grant authorization handler.
func RFC8628DeviceAuthorizationFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8628.DeviceAuthorizationHandler{
		Strategy: strategy.(rfc8628.RFC8628CodeStrategy),
		Storage:  storage.(rfc8628.RFC8628CodeStorage),
		Config:   config,
	}
}

// RFC8628DeviceUserVerificationFactory creates an OAuth2 device grant user interaction handler.
func RFC8628DeviceUserVerificationFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8628.DeviceUserVerificationHandler{
		Strategy: strategy.(rfc8628.RFC8628CodeStrategy),
		Storage:  storage.(rfc8628.RFC8628CodeStorage),
		Config:   config,
	}
}

// RFC8628DeviceAuthorizationTokenFactory creates an OAuth2 device authorization grant ("device authorization flow") handler and registers
// an access token, refresh token and authorize code validator.
func RFC8628DeviceAuthorizationTokenFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc8628.DeviceAuthorizationTokenEndpointHandler{
		GenericCodeTokenEndpointHandler: oauth2.GenericCodeTokenEndpointHandler{
			CodeTokenEndpointHandler: &rfc8628.DeviceCodeTokenHandler{
				Strategy: strategy.(rfc8628.RFC8628CodeStrategy),
				Storage:  storage.(rfc8628.RFC8628CodeStorage),
				Config:   config,
			},
			AccessTokenStrategy:    strategy.(oauth2.AccessTokenStrategy),
			RefreshTokenStrategy:   strategy.(oauth2.RefreshTokenStrategy),
			CoreStorage:            storage.(oauth2.CoreStorage),
			TokenRevocationStorage: storage.(oauth2.TokenRevocationStorage),
			Config:                 config,
		},
	}
}

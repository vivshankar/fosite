// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/rfc9396"
)

func RFC9396AuthorizeEndpointHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc9396.AuthorizeHandler{
		Config: config.(fosite.RFC9396ConfigProvider),
	}
}

func RFC9396TokenRequestEndpointHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc9396.TokenRequestHandler{
		Config: config.(fosite.RFC9396ConfigProvider),
	}
}

func RFC9396TokenResponseEndpointHandlerFactory(config fosite.Configurator, storage interface{}, strategy interface{}) interface{} {
	return &rfc9396.TokenResponseHandler{
		Config: config.(fosite.RFC9396ConfigProvider),
	}
}

// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"errors"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"
)

type OpenIDConnectDeviceAuthorizeHandler struct {
	OpenIDConnectRequestStorage   OpenIDConnectRequestStorage
	OpenIDConnectRequestValidator *OpenIDConnectRequestValidator
	oauth2.CodeTokenEndpointHandler

	Config interface {
		fosite.IDTokenLifespanProvider
	}

	*IDTokenHandleHelper
}

var (
	_ fosite.RFC8628UserAuthorizeEndpointHandler = (*OpenIDConnectDeviceAuthorizeHandler)(nil)
	_ fosite.TokenEndpointHandler                = (*OpenIDConnectDeviceAuthorizeHandler)(nil)
)

func (c *OpenIDConnectDeviceAuthorizeHandler) HandleRFC8628UserAuthorizeEndpointRequest(_ context.Context, _ fosite.DeviceAuthorizeRequester) error {
	return errorsx.WithStack(fosite.ErrUnknownRequest)
}

func (c *OpenIDConnectDeviceAuthorizeHandler) PopulateRFC8628UserAuthorizeEndpointResponse(ctx context.Context, req fosite.DeviceAuthorizeRequester, _ fosite.RFC8628UserAuthorizeResponder) error {
	if !(req.GetGrantedScopes().Has("openid")) {
		return nil
	}

	if !req.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return nil
	}

	if len(req.GetDeviceCodeSignature()) == 0 {
		return errorsx.WithStack(fosite.ErrMisconfiguration.WithDebug("The device code has not been issued yet, indicating a broken code configuration."))
	}

	if err := c.OpenIDConnectRequestStorage.CreateOpenIDConnectSession(ctx, req.GetDeviceCodeSignature(), req.Sanitize(oidcParameters)); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (c *OpenIDConnectDeviceAuthorizeHandler) HandleTokenEndpointRequest(_ context.Context, _ fosite.AccessRequester) error {
	return errorsx.WithStack(fosite.ErrUnknownRequest)
}

func (c *OpenIDConnectDeviceAuthorizeHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	signature, err := c.DeviceCodeSignature(ctx, requester.GetRequestForm().Get("device_code"))
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	authorize, err := c.OpenIDConnectRequestStorage.GetOpenIDConnectSession(ctx, signature, requester)
	if errors.Is(err, ErrNoSessionFound) {
		return errorsx.WithStack(fosite.ErrUnknownRequest.WithWrap(err).WithDebug(err.Error()))
	} else if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if !authorize.GetGrantedScopes().Has("openid") {
		return errorsx.WithStack(fosite.ErrMisconfiguration.WithDebug("An OpenID Connect session was found but the openid scope is missing, probably due to a broken code configuration."))
	}

	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant \"urn:ietf:params:oauth:grant-type:device_code\"."))
	}

	sess, ok := authorize.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate id token because session must be of type fosite/handler/openid.Session."))
	}

	claims := sess.IDTokenClaims()
	if claims.Subject == "" {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, requester, responder)

	idTokenLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.IDToken, c.Config.GetIDTokenLifespan(ctx))
	return c.IssueExplicitIDToken(ctx, idTokenLifespan, authorize, responder)
}

func (c *OpenIDConnectDeviceAuthorizeHandler) CanSkipClientAuth(_ context.Context, _ fosite.AccessRequester) bool {
	return false
}

func (c *OpenIDConnectDeviceAuthorizeHandler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

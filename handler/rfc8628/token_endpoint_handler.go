// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/x/errorsx"
	"time"
)

// DeviceCodeTokenHandler is a response handler for the Device Code introduced in the Device Authorize Grant
// as defined in https://www.rfc-editor.org/rfc/rfc8628
type DeviceCodeTokenHandler struct {
	Storage  RFC8628CodeStorage
	Strategy RFC8628CodeStrategy
	Config   interface {
		fosite.DeviceAuthorizationProvider
		fosite.DeviceAndUserCodeLifespanProvider
	}
}

type DeviceAuthorizationTokenEndpointHandler struct {
	oauth2.GenericCodeTokenEndpointHandler
}

var _ oauth2.CodeTokenEndpointHandler = (*DeviceCodeTokenHandler)(nil)

var _ fosite.TokenEndpointHandler = (*DeviceAuthorizationTokenEndpointHandler)(nil)

func (c *DeviceCodeTokenHandler) ValidateGrantTypes(_ context.Context, requester fosite.AccessRequester) error {
	if !requester.GetClient().GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"urn:ietf:params:oauth:grant-type:device_code\"."))
	}

	return nil
}

func (c *DeviceCodeTokenHandler) ValidateCodeAndSession(ctx context.Context, _ fosite.AccessRequester, authorizeRequest fosite.Requester, code string) error {
	return c.Strategy.ValidateDeviceCode(ctx, authorizeRequest, code)
}

func (c *DeviceCodeTokenHandler) GetCodeAndSession(ctx context.Context, requester fosite.AccessRequester) (string, string, fosite.Requester, error) {
	code := requester.GetRequestForm().Get("device_code")
	signature, err := c.Strategy.DeviceCodeSignature(ctx, code)
	if err != nil {
		return "", "", nil, errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	deviceAuthReq, err := c.Storage.GetDeviceCodeSession(ctx, signature, requester.GetSession())
	if err != nil {
		return "", "", nil, err
	}

	if deviceAuthReq.GetClient().GetID() != requester.GetClient().GetID() {
		return "", "", nil, errorsx.WithStack(fosite.ErrInvalidGrant.
			WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// check last requested time
	lastReqTime := deviceAuthReq.GetLastChecked()
	requestedAt := requester.GetRequestedAt()
	if requestedAt.IsZero() {
		requestedAt = time.Now()
	}
	pollInterval := c.Config.GetDeviceAuthTokenPollingInterval(ctx)
	if lastReqTime.Add(pollInterval).After(requestedAt) {
		_ = c.UpdateLastChecked(ctx, requester, deviceAuthReq)
		return code, signature, deviceAuthReq, errorsx.WithStack(
			fosite.ErrSlowDown.WithHintf(
				"The device made an attempt within [%d] seconds. This request will not be processed.",
				(int)(pollInterval.Seconds()),
			),
		)
	}

	// get the user code session
	userAuthReq, err := c.Storage.GetUserCodeSession(ctx, deviceAuthReq.GetUserCodeSignature(), requester.GetSession())
	if err != nil {
		_ = c.UpdateLastChecked(ctx, requester, deviceAuthReq)
		return code, signature, deviceAuthReq, err
	}

	if userAuthReq.GetStatus() == fosite.DeviceAuthorizationStatusNew {
		_ = c.UpdateLastChecked(ctx, requester, deviceAuthReq)
		return "", "", nil, errorsx.WithStack(fosite.ErrAuthorizationPending.WithHintf("The user has not authorized the request."))
	}

	// update status and session into access request and device authorization request
	deviceAuthReq.Merge(userAuthReq)
	requester.SetSession(deviceAuthReq.GetSession())
	requester.SetID(deviceAuthReq.GetID())

	if userAuthReq.GetStatus() != fosite.DeviceAuthorizationStatusApproved {
		return "", "", nil, errorsx.WithStack(fosite.ErrAccessDenied.WithHintf("The user has denied the request."))
	}

	return code, signature, deviceAuthReq, err
}

func (c *DeviceCodeTokenHandler) UpdateLastChecked(ctx context.Context, request fosite.AccessRequester, authorizeRequest fosite.Requester) error {
	session, _ := authorizeRequest.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform device authorization because the session is not of the right type."))
	}
	authReq, ok := authorizeRequest.(fosite.DeviceAuthorizationRequester)
	if !ok {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform device authorization because the authorizeRequest is not of the right type."))
	}
	lastChecked := request.GetRequestedAt()
	if lastChecked.IsZero() {
		lastChecked = time.Now()
	}
	authReq.SetLastChecked(request.GetRequestedAt())
	return c.Storage.UpdateDeviceCodeSession(ctx, authReq.GetDeviceCodeSignature(), authReq)
}

func (c *DeviceCodeTokenHandler) InvalidateSession(ctx context.Context, signature string, authorizeRequest fosite.Requester) error {
	if err := c.Storage.InvalidateDeviceCodeSession(ctx, signature); err != nil {
		return err
	}
	if authReq, ok := authorizeRequest.(fosite.DeviceAuthorizationRequester); ok {
		return c.Storage.InvalidateUserCodeSession(ctx, authReq.GetUserCodeSignature())
	}

	return nil
}

// implements CodeTokenEndpointHandler
func (c *DeviceCodeTokenHandler) CanSkipClientAuth(_ context.Context, _ fosite.AccessRequester) bool {
	return false
}

func (c *DeviceCodeTokenHandler) CanHandleTokenEndpointRequest(_ context.Context, requester fosite.AccessRequester) bool {
	return requester.GetGrantTypes().ExactOne(string(fosite.GrantTypeDeviceCode))
}

func (c *DeviceCodeTokenHandler) DeviceCodeSignature(ctx context.Context, code string) (string, error) {
	return c.Strategy.DeviceCodeSignature(ctx, code)
}

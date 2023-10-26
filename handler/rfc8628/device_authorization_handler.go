// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

type DeviceAuthorizationHandler struct {
	Storage  RFC8628CodeStorage
	Strategy RFC8628CodeStrategy
	Config   interface {
		fosite.DeviceAuthorizationProvider
		fosite.DeviceAndUserCodeLifespanProvider
	}
}

// HandleDeviceAuthorizationEndpointRequest is a response handler for the Device Authorisation Grant as
// defined in https://tools.ietf.org/html/rfc8628#section-3.1
func (d *DeviceAuthorizationHandler) HandleDeviceAuthorizationEndpointRequest(ctx context.Context, dar fosite.DeviceAuthorizationRequester, resp fosite.DeviceResponder) error {
	session, _ := dar.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform device authorization because the session is not of the right type."))
	}

	deviceCode, deviceCodeSignature, err := d.Strategy.GenerateDeviceCode(ctx)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	userCode, userCodeSignature, err := d.Strategy.GenerateUserCode(ctx)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	dar.SetStatus(fosite.DeviceAuthorizationStatusNew)

	dar.SetDeviceCodeSignature(deviceCodeSignature)
	dar.SetUserCodeSignature(userCodeSignature)

	expireAt := time.Now().UTC().Add(d.Config.GetDeviceAndUserCodeLifespan(ctx)).Round(time.Second)
	session.SetExpiresAt(fosite.DeviceCode, expireAt)
	session.SetExpiresAt(fosite.UserCode, expireAt)

	if err = d.Storage.CreateDeviceCodeSession(ctx, deviceCodeSignature, dar); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	if err = d.Storage.CreateUserCodeSession(ctx, userCodeSignature, dar); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// Populate the response fields
	resp.SetDeviceCode(deviceCode)
	resp.SetUserCode(userCode)
	resp.SetVerificationURI(d.Config.GetDeviceVerificationURL(ctx))
	resp.SetVerificationURIComplete(d.Config.GetDeviceVerificationURL(ctx) + "?user_code=" + userCode)
	resp.SetExpiresIn(int64(time.Until(expireAt).Seconds()))
	resp.SetInterval(int(d.Config.GetDeviceAuthTokenPollingInterval(ctx).Seconds()))
	return nil
}

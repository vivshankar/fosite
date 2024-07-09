// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
)

type DeviceAuthorizeHandler struct {
	Storage  RFC8628CodeStorage
	Strategy RFC8628CodeStrategy
	Config   interface {
		fosite.DeviceAuthorizeConfigProvider
	}
}

var _ fosite.DeviceAuthorizeEndpointHandler = (*DeviceAuthorizeHandler)(nil)

// HandleDeviceAuthorizeEndpointRequest is a response handler for the Device Authorisation Grant as
// defined in https://tools.ietf.org/html/rfc8628#section-3.1
func (d *DeviceAuthorizeHandler) HandleDeviceAuthorizeEndpointRequest(ctx context.Context, dar fosite.DeviceAuthorizeRequester, resp fosite.DeviceAuthorizeResponder) error {
	session := dar.GetSession()

	deviceCode, deviceCodeSignature, err := d.Strategy.GenerateDeviceCode(ctx)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	userCode, userCodeSignature, err := d.Strategy.GenerateUserCode(ctx)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	dar.SetStatus(fosite.DeviceAuthorizeStatusNew)

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
	resp.SetVerificationURI(d.Config.GetRFC8628UserVerificationURL(ctx))
	resp.SetVerificationURIComplete(d.formCompleteURI(d.Config.GetRFC8628UserVerificationURL(ctx), userCode))
	resp.SetExpiresIn(int64(time.Until(expireAt).Seconds()))
	resp.SetInterval(int(d.Config.GetDeviceAuthTokenPollingInterval(ctx).Seconds()))
	return nil
}

func (d *DeviceAuthorizeHandler) formCompleteURI(verificationURI, userCode string) string {
	u, _ := url.Parse(verificationURI)
	qp := u.Query()
	qp["user_code"] = []string{userCode}
	u.RawQuery = qp.Encode()
	return u.String()
}

// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"github.com/ory/fosite"
	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"
	"time"
)

type DeviceUserVerificationHandler struct {
	Storage  RFC8628CodeStorage
	Strategy RFC8628CodeStrategy
	Config   interface {
		fosite.DeviceAuthorizationProvider
		fosite.DeviceAndUserCodeLifespanProvider
	}
}

var (
	_ fosite.DeviceUserVerificationEndpointHandler = (*DeviceUserVerificationHandler)(nil)
)

// HandleDeviceUserVerificationEndpointRequest is a response handler for the Device Authorisation Grant as
// defined in https://tools.ietf.org/html/rfc8628#section-3.1
func (d *DeviceUserVerificationHandler) HandleDeviceUserVerificationEndpointRequest(ctx context.Context, req fosite.DeviceAuthorizationRequester, resp fosite.DeviceUserVerificationResponder) error {
	session, _ := req.GetSession().(Session)
	if session == nil {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to perform device authorization because the session is not of the right type."))
	}

	status := req.GetStatus()
	// the request shall be either approved or denied
	if status != fosite.DeviceAuthorizationStatusApproved && status != fosite.DeviceAuthorizationStatusDenied {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithDebug("Failed to perform device authorization because the request status is invalid."))
	}

	resp.SetStatus(fosite.DeviceAuthorizationStatusToString(status))

	// Stores the auth session and approval status into user code session instead of device code session.
	userCodeSignature := req.GetUserCodeSignature()
	if err := d.Storage.UpdateUserCodeSession(ctx, userCodeSignature, req); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

func (d *DeviceUserVerificationHandler) ValidateRequest(ctx context.Context, dur fosite.DeviceAuthorizationRequester) error {
	userCode := dur.GetRequestForm().Get("user_code")
	if len(userCode) == 0 {
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Cannot process the request, user_code is missing."))
	}

	userCodeSig, err := d.Strategy.UserCodeSignature(ctx, userCode)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	storedReq, err := d.Storage.GetUserCodeSession(ctx, userCodeSig, dur.GetSession())
	if errors.Is(err, fosite.ErrNotFound) {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("Cannot process the request, the user_code is either invalid or expired."))
	} else if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	dur.Merge(storedReq)
	client := dur.GetClient()
	if !client.GetGrantTypes().Has(string(fosite.GrantTypeDeviceCode)) { // shall not happen?
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The requested OAuth 2.0 Client does not have the 'urn:ietf:params:oauth:grant-type:device_code' grant."))
	}

	session, _ := dur.GetSession().(Session)
	if session == nil { // shall not happen?
		return errorsx.WithStack(fosite.ErrServerError.WithHint("Failed to validate session because the session is not of the right type."))
	}
	if dur.GetUserCodeSignature() != userCodeSig { // shall not happen?
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithHint("Cannot process the request, user code signature mismatching."))
	}
	if session.GetExpiresAt(fosite.UserCode).Before(time.Now().UTC()) || dur.GetStatus() != fosite.DeviceAuthorizationStatusNew {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("Cannot process the request, the user_code is either invalid or expired."))
	}

	return nil
}

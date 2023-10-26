// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"errors"
	"github.com/ory/fosite/i18n"
	"github.com/ory/x/errorsx"
	"net/http"
)

func (f *Fosite) NewDeviceUserVerificationRequest(ctx context.Context, req *http.Request) (DeviceAuthorizationRequester, error) {
	request := NewDeviceAuthorizationRequest()
	request.Lang = i18n.GetLangFromRequest(f.Config.GetMessageCatalog(ctx), req)

	if err := req.ParseForm(); err != nil {
		return nil, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebug(err.Error()))
	}
	request.Form = req.Form

	for _, h := range f.Config.GetDeviceUserVerificationEndpointHandlers(ctx) {
		if err := h.ValidateRequest(ctx, request); err != nil && !errors.Is(err, ErrUnknownRequest) {
			return nil, err
		}
	}

	return request, nil
}

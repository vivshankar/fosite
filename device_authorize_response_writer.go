// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
)

func (f *Fosite) NewDeviceAuthorizeResponse(ctx context.Context, r DeviceAuthorizeRequester, session Session) (DeviceAuthorizeResponder, error) {
	r.SetSession(session)
	var resp = NewDeviceAuthorizeResponse()

	for _, h := range f.Config.GetDeviceAuthorizeEndpointHandlers(ctx) {
		if err := h.HandleDeviceAuthorizeEndpointRequest(ctx, r, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

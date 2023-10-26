// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
)

func (f *Fosite) NewDeviceAuthorizationResponse(ctx context.Context, r DeviceAuthorizationRequester, session Session) (DeviceResponder, error) {
	r.SetSession(session)
	var resp = NewDeviceAuthorizationResponse()

	for _, h := range f.Config.GetDeviceAuthorizationEndpointHandlers(ctx) {
		if err := h.HandleDeviceAuthorizationEndpointRequest(ctx, r, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

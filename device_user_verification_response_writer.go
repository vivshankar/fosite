// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import "context"

func (f *Fosite) NewDeviceUserVerificationResponse(ctx context.Context, requester DeviceAuthorizationRequester, session Session) (DeviceUserVerificationResponder, error) {
	requester.SetSession(session)
	var resp = NewDeviceUserVerificationResponse()

	for _, h := range f.Config.GetDeviceUserVerificationEndpointHandlers(ctx) {
		if err := h.HandleDeviceUserVerificationEndpointRequest(ctx, requester, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

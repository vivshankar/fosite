// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import "context"

func (f *Fosite) NewRFC8628UserAuthorizeResponse(ctx context.Context, requester DeviceAuthorizeRequester, session Session) (RFC8628UserAuthorizeResponder, error) {
	requester.SetSession(session)
	var resp = NewRFC8628UserAuthorizeResponse()

	for _, h := range f.Config.GetRFC8628UserAuthorizeEndpointHandlers(ctx) {
		if err := h.PopulateRFC8628UserAuthorizeEndpointResponse(ctx, requester, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

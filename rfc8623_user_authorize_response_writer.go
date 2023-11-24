// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import "context"

func (f *Fosite) NewRFC8623UserAuthorizeResponse(ctx context.Context, requester DeviceAuthorizeRequester, session Session) (RFC8623UserAuthorizeResponder, error) {
	requester.SetSession(session)
	var resp = NewRFC8623UserAuthorizeResponse()

	for _, h := range f.Config.GetRFC8623UserAuthorizeEndpointHandlers(ctx) {
		if err := h.PopulateRFC8623UserAuthorizeEndpointResponse(ctx, requester, resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628_test

import (
	"context"
	"fmt"
	"github.com/ory/fosite/handler/openid"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	. "github.com/ory/fosite/handler/rfc8628"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/assert"
)

func Test_HandleDeviceEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	store := storage.NewMemoryStore()
	handler := DeviceAuthorizationHandler{
		Storage:  store,
		Strategy: &hmacshaStrategy,
		Config: &fosite.Config{
			DeviceAndUserCodeLifespan:      time.Minute * 10,
			DeviceAuthTokenPollingInterval: time.Second * 10,
			DeviceVerificationURL:          "https://www.test.com",
			AccessTokenLifespan:            time.Hour,
			RefreshTokenLifespan:           time.Hour,
			ScopeStrategy:                  fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
			RefreshTokenScopes:             []string{"offline"},
		},
	}

	req := fosite.NewDeviceAuthorizationRequest()
	req.SetSession(&DefaultSession{
		DefaultSession: openid.NewDefaultSession(),
	})

	resp := &fosite.DeviceAuthorizationResponse{Extra: map[string]interface{}{}}

	err := handler.HandleDeviceAuthorizationEndpointRequest(context.TODO(), req, resp)

	assert.NoError(t, err)
	assert.NotEmpty(t, resp.GetDeviceCode())
	assert.NotEmpty(t, resp.GetUserCode())
	assert.Equal(t, 8, len(resp.GetUserCode()))
	assert.Contains(t, resp.GetDeviceCode(), "ory_dc_")
	assert.Contains(t, resp.GetDeviceCode(), ".")
	assert.Equal(t, "https://www.test.com", resp.GetVerificationURI())
	assert.Equal(t, fmt.Sprintf("https://www.test.com?user_code=%s", resp.GetUserCode()), resp.GetVerificationURIComplete())
	assert.Equal(t, 10, resp.GetInterval())
}

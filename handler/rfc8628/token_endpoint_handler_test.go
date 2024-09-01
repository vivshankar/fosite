// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing" //"time"

	"github.com/golang/mock/gomock"
	"github.com/ory/fosite/handler/openid"
	. "github.com/ory/fosite/handler/rfc8628"
	"github.com/ory/fosite/internal"

	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/hmac"

	//"github.com/golang/mock/gomock"
	"time"

	"github.com/ory/fosite" //"github.com/ory/fosite/internal"
	"github.com/ory/fosite/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var o2hmacshaStrategy = oauth2.HMACSHAStrategy{
	Enigma: &hmac.HMACStrategy{Config: &fosite.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	Config: &fosite.Config{
		AccessTokenLifespan:   time.Hour * 24,
		AuthorizeCodeLifespan: time.Hour * 24,
	},
}

var RFC8628HMACSHAStrategy = DefaultDeviceStrategy{
	Enigma: &hmac.HMACStrategy{Config: &fosite.Config{GlobalSecret: []byte("foobarfoobarfoobarfoobarfoobarfoobarfoobarfoobar")}},
	Config: &fosite.Config{
		DeviceAndUserCodeLifespan: time.Hour * 24,
	},
}

func TestDeviceAuthorizeCode_PopulateTokenEndpointResponse(t *testing.T) {
	for k, strategy := range map[string]struct {
		oauth2.CoreStrategy
		RFC8628CodeStrategy
	}{
		"hmac": {&o2hmacshaStrategy, &RFC8628HMACSHAStrategy},
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()

			var h oauth2.GenericCodeTokenEndpointHandler
			for _, c := range []struct {
				areq        *fosite.AccessRequest
				description string
				setup       func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config)
				check       func(t *testing.T, aresp *fosite.AccessResponse)
				expectErr   error
			}{
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"123"},
					},
					description: "should fail because not responsible",
					expectErr:   fosite.ErrUnknownRequest,
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because device code not found",
					setup: func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config) {
						code, _, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form.Set("device_code", code)
					},
					expectErr: fosite.ErrServerError,
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
							},
							GrantedScope: fosite.Arguments{"foo", "offline"},
							Session:      &fosite.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config) {
						dar := fosite.NewDeviceAuthorizeRequest()
						dar.Merge(areq)
						dCode, dSig, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateUserCode(context.TODO())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, dar))
						dar.SetStatus(fosite.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateUserCodeSession(context.TODO(), uSig, dar))

						areq.Form.Add("device_code", dCode)
					},
					description: "should pass with offline scope and refresh token",
					check: func(t *testing.T, aresp *fosite.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.NotEmpty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo offline", aresp.GetExtra("scope"))
					},
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
							},
							GrantedScope: fosite.Arguments{"foo"},
							Session:      &fosite.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config) {
						config.RefreshTokenScopes = []string{}

						dar := fosite.NewDeviceAuthorizeRequest()
						dar.Merge(areq)
						dCode, dSig, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateUserCode(context.TODO())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, dar))
						dar.SetStatus(fosite.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateUserCodeSession(context.TODO(), uSig, dar))

						areq.Form.Add("device_code", dCode)
					},
					description: "should pass with refresh token always provided",
					check: func(t *testing.T, aresp *fosite.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.NotEmpty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo", aresp.GetExtra("scope"))
					},
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							GrantedScope: fosite.Arguments{},
							Session:      &fosite.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config) {
						config.RefreshTokenScopes = []string{}

						dar := fosite.NewDeviceAuthorizeRequest()
						dar.Merge(areq)
						dCode, dSig, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateUserCode(context.TODO())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, dar))
						dar.SetStatus(fosite.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateUserCodeSession(context.TODO(), uSig, dar))

						areq.Form.Add("device_code", dCode)
					},
					description: "should pass with no refresh token",
					check: func(t *testing.T, aresp *fosite.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.Empty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Empty(t, aresp.GetExtra("scope"))
					},
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							GrantedScope: fosite.Arguments{"foo"},
							Session:      &fosite.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, config *fosite.Config) {
						dar := fosite.NewDeviceAuthorizeRequest()
						dar.Merge(areq)
						dCode, dSig, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateUserCode(context.TODO())
						require.NoError(t, err)
						dar.SetDeviceCodeSignature(dSig)
						dar.SetUserCodeSignature(uSig)

						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, dar))
						dar.SetStatus(fosite.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateUserCodeSession(context.TODO(), uSig, dar))

						areq.Form.Add("device_code", dCode)
					},
					description: "should not have refresh token",
					check: func(t *testing.T, aresp *fosite.AccessResponse) {
						assert.NotEmpty(t, aresp.AccessToken)
						assert.Equal(t, "bearer", aresp.TokenType)
						assert.Empty(t, aresp.GetExtra("refresh_token"))
						assert.NotEmpty(t, aresp.GetExtra("expires_in"))
						assert.Equal(t, "foo", aresp.GetExtra("scope"))
					},
				},
			} {
				t.Run("case="+c.description, func(t *testing.T) {
					config := &fosite.Config{
						ScopeStrategy:            fosite.HierarchicScopeStrategy,
						AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
						AccessTokenLifespan:      time.Minute,
						RefreshTokenScopes:       []string{"offline"},
					}
					h = oauth2.GenericCodeTokenEndpointHandler{
						CodeTokenEndpointHandler: &DeviceCodeTokenHandler{
							Strategy: strategy,
							Storage:  store,
							Config:   config,
						},
						AccessTokenStrategy:    strategy.CoreStrategy,
						RefreshTokenStrategy:   strategy.CoreStrategy,
						Config:                 config,
						CoreStorage:            store,
						TokenRevocationStorage: store,
					}

					if c.setup != nil {
						c.setup(t, c.areq, config)
					}

					aresp := fosite.NewAccessResponse()
					err := h.PopulateTokenEndpointResponse(context.TODO(), c.areq, aresp)

					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
					}

					if c.check != nil {
						c.check(t, aresp)
					}
				})
			}
		})
	}
}

func TestDeviceAuthorizeCode_HandleTokenEndpointRequest(t *testing.T) {
	for k, strategy := range map[string]struct {
		oauth2.CoreStrategy
		RFC8628CodeStrategy
	}{
		"hmac": {&o2hmacshaStrategy, &RFC8628HMACSHAStrategy},
	} {
		t.Run("strategy="+k, func(t *testing.T) {
			store := storage.NewMemoryStore()
			config := &fosite.Config{
				ScopeStrategy:            fosite.HierarchicScopeStrategy,
				AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
				AccessTokenLifespan:      time.Minute,
				RefreshTokenScopes:       []string{"offline"},
			}
			h := oauth2.GenericCodeTokenEndpointHandler{
				CodeTokenEndpointHandler: &DeviceCodeTokenHandler{
					Strategy: strategy,
					Storage:  store,
					Config:   config,
				},
				CoreStorage:          store,
				AccessTokenStrategy:  strategy.CoreStrategy,
				RefreshTokenStrategy: strategy.CoreStrategy,
				Config:               config,
			}
			for i, c := range []struct {
				areq        *fosite.AccessRequest
				authreq     *fosite.DeviceAuthorizeRequest
				description string
				setup       func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceAuthorizeRequest)
				check       func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceAuthorizeRequest)
				expectErr   error
			}{
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"12345678"},
					},
					description: "should fail because not responsible",
					expectErr:   fosite.ErrUnknownRequest,
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{""}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because client is not granted this grant type",
					expectErr:   fosite.ErrUnauthorizedClient,
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because device code could not be retrieved",
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceAuthorizeRequest) {
						deviceCode, _, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						areq.Form = url.Values{"device_code": {deviceCode}}
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form:        url.Values{"device_code": {"AAAA"}},
							Client:      &fosite.DefaultClient{GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					description: "should fail because device code validation failed",
					expectErr:   fosite.ErrInvalidGrant,
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.DeviceAuthorizeRequest{
						Request: fosite.Request{
							Client:         &fosite.DefaultClient{ID: "bar"},
							RequestedScope: fosite.Arguments{"a", "b"},
							Session:        openid.NewDefaultSession(),
						},
					},
					description: "should fail because client mismatch",
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceAuthorizeRequest) {
						dCode, dSig, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateUserCode(context.TODO())
						require.NoError(t, err)
						authreq.SetDeviceCodeSignature(dSig)
						authreq.SetUserCodeSignature(uSig)
						authreq.GetSession().SetExpiresAt(fosite.UserCode, time.Now().UTC().Add(time.Hour))
						authreq.GetSession().SetExpiresAt(fosite.DeviceCode, time.Now().UTC().Add(time.Hour))
						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, authreq))
						authreq.SetStatus(fosite.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateUserCodeSession(context.TODO(), uSig, authreq))

						areq.Form = url.Values{"device_code": {dCode}}
					},
					expectErr: fosite.ErrInvalidGrant,
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:     &fosite.DefaultSession{},
							RequestedAt: time.Now().UTC(),
						},
					},
					authreq: &fosite.DeviceAuthorizeRequest{
						Request: fosite.Request{
							Client:         &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}},
							Session:        &fosite.DefaultSession{},
							RequestedScope: fosite.Arguments{"a", "b"},
							RequestedAt:    time.Now().UTC(),
						},
					},
					description: "should pass",
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceAuthorizeRequest) {
						dCode, dSig, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateUserCode(context.TODO())
						require.NoError(t, err)
						authreq.SetDeviceCodeSignature(dSig)
						authreq.SetUserCodeSignature(uSig)
						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, authreq))
						authreq.SetStatus(fosite.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateUserCodeSession(context.TODO(), uSig, authreq))

						areq.Form = url.Values{"device_code": {dCode}}
					},
				},
				{
					areq: &fosite.AccessRequest{
						GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
						Request: fosite.Request{
							Form: url.Values{},
							Client: &fosite.DefaultClient{
								GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
							},
							GrantedScope: fosite.Arguments{"foo", "offline"},
							Session:      &fosite.DefaultSession{},
							RequestedAt:  time.Now().UTC(),
						},
					},
					check: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceAuthorizeRequest) {
						assert.Equal(t, time.Now().Add(time.Minute).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(fosite.AccessToken))
						assert.Equal(t, time.Now().Add(time.Minute).UTC().Round(time.Second), areq.GetSession().GetExpiresAt(fosite.RefreshToken))
					},
					setup: func(t *testing.T, areq *fosite.AccessRequest, authreq *fosite.DeviceAuthorizeRequest) {
						authreq = fosite.NewDeviceAuthorizeRequest()
						authreq.SetSession(openid.NewDefaultSession())
						authreq.GetSession().SetExpiresAt(fosite.UserCode,
							time.Now().Add(-time.Hour).UTC().Round(time.Second))
						authreq.GetSession().SetExpiresAt(fosite.DeviceCode,
							time.Now().Add(-time.Hour).UTC().Round(time.Second))
						dCode, dSig, err := strategy.GenerateDeviceCode(context.TODO())
						require.NoError(t, err)
						_, uSig, err := strategy.GenerateUserCode(context.TODO())
						require.NoError(t, err)
						authreq.SetDeviceCodeSignature(dSig)
						authreq.SetUserCodeSignature(uSig)
						require.NoError(t, store.CreateDeviceCodeSession(context.TODO(), dSig, authreq))
						authreq.SetStatus(fosite.DeviceAuthorizeStatusApproved)
						require.NoError(t, store.CreateUserCodeSession(context.TODO(), uSig, authreq))

						areq.Form.Add("device_code", dCode)
					},
					description: "should fail because device code has expired",
					expectErr:   fosite.ErrDeviceExpiredToken,
				},
			} {
				t.Run(fmt.Sprintf("case=%d/description=%s", i, c.description), func(t *testing.T) {
					if c.setup != nil {
						c.setup(t, c.areq, c.authreq)
					}

					t.Logf("Processing %+v", c.areq.Client)

					err := h.HandleTokenEndpointRequest(context.Background(), c.areq)
					if c.expectErr != nil {
						require.EqualError(t, err, c.expectErr.Error(), "%+v", err)
					} else {
						require.NoError(t, err, "%+v", err)
						if c.check != nil {
							c.check(t, c.areq, c.authreq)
						}
					}
				})
			}
		})
	}
}

func TestDeviceAuthorizeCodeTransactional_HandleTokenEndpointRequest(t *testing.T) {
	var mockTransactional *internal.MockTransactional
	var mockCoreStore *internal.MockCoreStorage
	var mockDeviceStore *internal.MockRFC8628CodeStorage
	strategy := o2hmacshaStrategy
	deviceStrategy := RFC8628HMACSHAStrategy
	request := &fosite.AccessRequest{
		GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
		Request: fosite.Request{
			Client: &fosite.DefaultClient{
				GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
			},
			GrantedScope: fosite.Arguments{"offline"},
			Session:      &fosite.DefaultSession{},
			RequestedAt:  time.Now().UTC(),
		},
	}
	deviceAuthReq := &fosite.DeviceAuthorizeRequest{
		Request: fosite.Request{
			Client: &fosite.DefaultClient{
				GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
			},
			GrantedScope: fosite.Arguments{"offline"},
			Session:      &fosite.DefaultSession{},
			RequestedAt:  time.Now().UTC(),
		},
		Status: fosite.DeviceAuthorizeStatusApproved,
	}
	token, _, err := deviceStrategy.GenerateDeviceCode(context.TODO())
	require.NoError(t, err)
	request.Form = url.Values{"device_code": {token}}
	response := fosite.NewAccessResponse()
	propagatedContext := context.Background()

	// some storage implementation that has support for transactions, notice the embedded type `storage.Transactional`
	type coreTransactionalStore struct {
		storage.Transactional
		oauth2.CoreStorage
	}

	type deviceTransactionalStore struct {
		storage.Transactional
		RFC8628CodeStorage
	}

	for _, testCase := range []struct {
		description string
		setup       func()
		expectError error
	}{
		{
			description: "transaction should be committed successfully if no errors occur",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					InvalidateUserCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(nil).
					Times(1)
			},
		},
		{
			description: "transaction should be rolled back if `InvalidateDeviceCodeSession` returns an error",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: fosite.ErrServerError,
		},
		{
			description: "transaction should be rolled back if `CreateAccessTokenSession` returns an error",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					InvalidateUserCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: fosite.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be created",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(nil, errors.New("Whoops, unable to create transaction!"))
			},
			expectError: fosite.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be rolled back",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
					Return(errors.New("Whoops, a nasty database error occurred!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(errors.New("Whoops, unable to rollback transaction!")).
					Times(1)
			},
			expectError: fosite.ErrServerError,
		},
		{
			description: "should result in a server error if transaction cannot be committed",
			setup: func() {
				mockDeviceStore.
					EXPECT().
					GetDeviceCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					GetUserCodeSession(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(deviceAuthReq, nil).
					Times(1)
				mockTransactional.
					EXPECT().
					BeginTX(propagatedContext).
					Return(propagatedContext, nil)
				mockDeviceStore.
					EXPECT().
					InvalidateDeviceCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockDeviceStore.
					EXPECT().
					InvalidateUserCodeSession(gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateAccessTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockCoreStore.
					EXPECT().
					CreateRefreshTokenSession(propagatedContext, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)
				mockTransactional.
					EXPECT().
					Commit(propagatedContext).
					Return(errors.New("Whoops, unable to commit transaction!")).
					Times(1)
				mockTransactional.
					EXPECT().
					Rollback(propagatedContext).
					Return(nil).
					Times(1)
			},
			expectError: fosite.ErrServerError,
		},
	} {
		t.Run(fmt.Sprintf("scenario=%s", testCase.description), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockTransactional = internal.NewMockTransactional(ctrl)
			mockCoreStore = internal.NewMockCoreStorage(ctrl)
			mockDeviceStore = internal.NewMockRFC8628CodeStorage(ctrl)
			testCase.setup()
			handler := oauth2.GenericCodeTokenEndpointHandler{
				CodeTokenEndpointHandler: &DeviceCodeTokenHandler{
					Strategy: &deviceStrategy,
					Storage: deviceTransactionalStore{
						mockTransactional,
						mockDeviceStore,
					},
					Config: &fosite.Config{
						ScopeStrategy:            fosite.HierarchicScopeStrategy,
						AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
						AccessTokenLifespan:      time.Minute,
						RefreshTokenScopes:       []string{"offline"},
					},
				},
				CoreStorage: coreTransactionalStore{
					mockTransactional,
					mockCoreStore,
				},
				AccessTokenStrategy:  &strategy,
				RefreshTokenStrategy: &strategy,
				Config: &fosite.Config{
					ScopeStrategy:             fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:  fosite.DefaultAudienceMatchingStrategy,
					DeviceAndUserCodeLifespan: time.Minute,
				},
			}

			if err := handler.PopulateTokenEndpointResponse(propagatedContext, request, response); testCase.expectError != nil {
				assert.EqualError(t, err, testCase.expectError.Error())
			}
		})
	}
}

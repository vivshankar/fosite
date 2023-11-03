// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"fmt"
	"github.com/golang/mock/gomock"
	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOpenIDConnectDeviceAuthorizationHandler_HandleDeviceUserVerificationEndpointRequest(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config := &fosite.Config{
		AccessTokenLifespan:       time.Minute * 24,
		AuthorizeCodeLifespan:     time.Minute * 24,
		DeviceAndUserCodeLifespan: time.Minute * 24,
	}
	j := &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (interface{}, error) {
				return key, nil
			},
		},
		Config: config,
	}

	oidcStore := internal.NewMockOpenIDConnectRequestStorage(ctrl)
	tokenHandler := internal.NewMockCodeTokenEndpointHandler(ctrl)

	handler := &OpenIDConnectDeviceAuthorizationHandler{
		OpenIDConnectRequestStorage:   oidcStore,
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Signer, config),
		CodeTokenEndpointHandler:      tokenHandler,
		Config:                        config,
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
	}
	req := fosite.NewDeviceAuthorizationRequest()
	resp := fosite.NewDeviceUserVerificationResponse()

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "Success",
			setup: func() {
				req.GrantedScope = []string{"openid"}
				req.Client = &fosite.DefaultClient{
					GrantTypes: []string{string(fosite.GrantTypeDeviceCode), string(fosite.GrantTypeAuthorizationCode)},
				}
				req.SetDeviceCodeSignature("foobar")
				oidcStore.EXPECT().CreateOpenIDConnectSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
		},
		{
			description: "Success - no openid scope",
			setup: func() {
				req.GrantedScope = []string{"foobar"}
			},
		},
		{
			description: "Success - client does not support device code grant type",
			setup: func() {
				req.GrantedScope = []string{"openid", "foobar"}
				req.Client = &fosite.DefaultClient{
					GrantTypes: []string{string(fosite.GrantTypeImplicit)},
				}
			},
		},
		{
			description: "Fail - request does not have device signature",
			setup: func() {
				req.GrantedScope = []string{"openid", "foobar"}
				req.Client = &fosite.DefaultClient{
					GrantTypes: []string{string(fosite.GrantTypeDeviceCode)},
				}
				req.SetDeviceCodeSignature("")
			},
			expectErr: fosite.ErrMisconfiguration.WithDebug("The device code has not been issued yet, indicating a broken code configuration."),
		},
		{
			description: "Fail - failed to create OIDC session",
			setup: func() {
				req.GrantedScope = []string{"openid"}
				req.Client = &fosite.DefaultClient{
					GrantTypes: []string{string(fosite.GrantTypeDeviceCode), string(fosite.GrantTypeAuthorizationCode)},
				}
				req.SetDeviceCodeSignature("foobar")
				oidcStore.EXPECT().CreateOpenIDConnectSession(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("foobar"))
			},
			expectErr: fosite.ErrServerError.WithDebug("foobar"),
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			err := handler.HandleDeviceUserVerificationEndpointRequest(context.TODO(), req, resp)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOpenIDConnectDeviceAuthorizationHandler_PopulateTokenEndpointResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config := &fosite.Config{
		AccessTokenLifespan:       time.Minute * 24,
		AuthorizeCodeLifespan:     time.Minute * 24,
		DeviceAndUserCodeLifespan: time.Minute * 24,
	}
	j := &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (interface{}, error) {
				return key, nil
			},
		},
		Config: config,
	}

	oidcStore := internal.NewMockOpenIDConnectRequestStorage(ctrl)
	tokenHandler := internal.NewMockCodeTokenEndpointHandler(ctrl)

	handler := &OpenIDConnectDeviceAuthorizationHandler{
		OpenIDConnectRequestStorage:   oidcStore,
		OpenIDConnectRequestValidator: NewOpenIDConnectRequestValidator(j.Signer, config),
		CodeTokenEndpointHandler:      tokenHandler,
		Config:                        config,
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
	}
	var (
		req     *fosite.AccessRequest
		resp    *fosite.AccessResponse
		authReq *fosite.AuthorizeRequest
	)

	for k, c := range []struct {
		description string
		setup       func()
		expectErr   error
	}{
		{
			description: "Success",
			setup: func() {
				sess := &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						RequestedAt: time.Now().UTC(),
						Subject:     "foobar",
					},
					Headers: &jwt.Headers{},
				}

				req = fosite.NewAccessRequest(nil)
				req.GrantedScope = []string{"openid"}
				req.GrantTypes = []string{string(fosite.GrantTypeDeviceCode)}
				req.Session = sess
				req.Client = &fosite.DefaultClient{
					GrantTypes: []string{string(fosite.GrantTypeDeviceCode), string(fosite.GrantTypeAuthorizationCode)},
				}

				resp = fosite.NewAccessResponse()

				authReq = fosite.NewAuthorizeRequest()
				authReq.GrantedScope = []string{"openid"}
				authReq.Session = sess

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
			},
		},
		{
			description: "Failed - request has no device code grant type ",
			setup: func() {
				req = fosite.NewAccessRequest(nil)
				req.GrantedScope = []string{"openid"}
				req.GrantTypes = []string{string(fosite.GrantTypeAuthorizationCode)}
			},
			expectErr: fosite.ErrUnknownRequest,
		},
		{
			description: "Failed - no device code",
			setup: func() {
				req = fosite.NewAccessRequest(nil)
				req.GrantTypes = []string{string(fosite.GrantTypeDeviceCode)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("", errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "Failed - get OIDC session ErrNoSessionFound",
			setup: func() {
				req = fosite.NewAccessRequest(nil)
				req.GrantTypes = []string{string(fosite.GrantTypeDeviceCode)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(nil, ErrNoSessionFound)
			},
			expectErr: fosite.ErrUnknownRequest,
		},
		{
			description: "Failed - get OIDC session other error",
			setup: func() {
				req = fosite.NewAccessRequest(nil)
				req.GrantTypes = []string{string(fosite.GrantTypeDeviceCode)}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(nil, errors.New(""))
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "Failed - auth request has no openid scope granted",
			setup: func() {
				req = fosite.NewAccessRequest(nil)
				req.GrantTypes = []string{string(fosite.GrantTypeDeviceCode)}

				resp = fosite.NewAccessResponse()

				authReq = fosite.NewAuthorizeRequest()
				authReq.GrantedScope = []string{"foobar"}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
			},
			expectErr: fosite.ErrMisconfiguration,
		},
		{
			description: "Failed - client has no device code grant type",
			setup: func() {
				req = fosite.NewAccessRequest(nil)
				req.GrantedScope = []string{"openid"}
				req.GrantTypes = []string{string(fosite.GrantTypeDeviceCode)}
				req.Client = &fosite.DefaultClient{
					GrantTypes: []string{string(fosite.GrantTypeAuthorizationCode)},
				}

				resp = fosite.NewAccessResponse()

				authReq = fosite.NewAuthorizeRequest()
				authReq.GrantedScope = []string{"openid"}

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
			},
			expectErr: fosite.ErrUnauthorizedClient,
		},
		{
			description: "Failed - no session",
			setup: func() {
				req = fosite.NewAccessRequest(nil)
				req.GrantedScope = []string{"openid"}
				req.GrantTypes = []string{string(fosite.GrantTypeDeviceCode)}
				req.Session = nil
				req.Client = &fosite.DefaultClient{
					GrantTypes: []string{string(fosite.GrantTypeDeviceCode), string(fosite.GrantTypeAuthorizationCode)},
				}

				resp = fosite.NewAccessResponse()

				authReq = fosite.NewAuthorizeRequest()
				authReq.GrantedScope = []string{"openid"}
				authReq.Session = nil

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
			},
			expectErr: fosite.ErrServerError,
		},
		{
			description: "Failed - ID Token Claim has no subject",
			setup: func() {
				sess := &DefaultSession{
					Claims: &jwt.IDTokenClaims{
						RequestedAt: time.Now().UTC(),
						Subject:     "",
					},
					Headers: &jwt.Headers{},
				}

				req = fosite.NewAccessRequest(nil)
				req.GrantedScope = []string{"openid"}
				req.GrantTypes = []string{string(fosite.GrantTypeDeviceCode)}
				req.Session = sess
				req.Client = &fosite.DefaultClient{
					GrantTypes: []string{string(fosite.GrantTypeDeviceCode), string(fosite.GrantTypeAuthorizationCode)},
				}

				resp = fosite.NewAccessResponse()

				authReq = fosite.NewAuthorizeRequest()
				authReq.GrantedScope = []string{"openid"}
				authReq.Session = sess

				tokenHandler.EXPECT().DeviceCodeSignature(gomock.Any(), gomock.Any()).Return("foobar", nil)
				oidcStore.EXPECT().GetOpenIDConnectSession(gomock.Any(), "foobar", req).Return(authReq, nil)
			},
			expectErr: fosite.ErrServerError,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			c.setup()
			err := handler.PopulateTokenEndpointResponse(context.TODO(), req, resp)

			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}
		})
	}
}

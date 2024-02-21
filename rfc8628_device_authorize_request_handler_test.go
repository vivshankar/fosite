// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/fosite"
	. "github.com/ory/fosite/internal"
)

type mockConfig struct {
	Config
	AuthenticateClient bool
}

func (c *mockConfig) ShouldAuthenticateClientOnDeviceAuthorize(_ context.Context) bool {
	return c.AuthenticateClient
}

func TestNewDeviceAuthorizeRequest(t *testing.T) {
	var store *MockStorage
	config := Config{ScopeStrategy: ExactScopeStrategy, AudienceMatchingStrategy: DefaultAudienceMatchingStrategy}
	for k, c := range []struct {
		desc          string
		conf          *Fosite
		r             *http.Request
		query         url.Values
		expectedError error
		ErrorHint     string
		mock          func()
		expect        *DeviceAuthorizeRequest
	}{
		/* empty request */
		{
			desc:          "empty request fails",
			conf:          &Fosite{Store: store, Config: &mockConfig{Config: config, AuthenticateClient: false}},
			expectedError: ErrInvalidClient,
			ErrorHint:     "The requested OAuth 2.0 Client does not exist.",
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* invalid client */
		{
			desc: "invalid client fails",
			conf: &Fosite{Store: store, Config: &mockConfig{Config: config, AuthenticateClient: false}},
			r: &http.Request{
				PostForm: url.Values{
					"client_id": {"1234"},
					"scope":     {"foo bar"},
				},
			},
			expectedError: ErrInvalidClient,
			ErrorHint:     "The requested OAuth 2.0 Client does not exist.",
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(nil, errors.New("foo"))
			},
		},
		/* invalid client - authentication fails */
		{
			desc: "invalid client - authentication fails",
			conf: &Fosite{Store: store, Config: &mockConfig{Config: config, AuthenticateClient: true}},
			r: &http.Request{
				PostForm: url.Values{
					"client_id":     {"1234"},
					"client_secret": {"foobar1234"},
					"scope":         {"foo bar"},
				},
			},
			expectedError: ErrInvalidClient,
			ErrorHint:     "The requested OAuth 2.0 Client could not be authenticated.",
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(&DefaultOpenIDConnectClient{
					DefaultClient: &DefaultClient{
						ID:         "1234",
						Secret:     []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
						GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
						Scopes:     []string{"foo", "bar"},
					},
					TokenEndpointAuthMethod: "client_secret_post",
				}, nil)
			},
		},
		/* fails because scope not given */
		{
			desc: "should fail because client does not have scope baz",
			conf: &Fosite{Store: store, Config: &mockConfig{Config: config, AuthenticateClient: false}},
			r: &http.Request{
				PostForm: url.Values{
					"client_id": {"1234"},
					"scope":     {"foo bar baz"},
				},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
					Scopes:     []string{"foo", "bar"},
				}, nil)
			},
			expectedError: ErrInvalidScope,
		},
		/* success case */
		{
			desc: "should pass",
			conf: &Fosite{Store: store, Config: &mockConfig{Config: config, AuthenticateClient: false}},
			r: &http.Request{
				PostForm: url.Values{
					"client_id": {"1234"},
					"scope":     {"foo bar"},
				},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					Scopes:     []string{"foo", "bar"},
					GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
				}, nil)
			},
			expect: &DeviceAuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{
						Scopes: []string{"foo", "bar"},
					},
					RequestedScope: []string{"foo", "bar"},
				},
			},
		},
		/* success with client auth */
		{
			desc: "success with client auth",
			conf: &Fosite{Store: store, Config: &mockConfig{Config: config, AuthenticateClient: true}},
			r: &http.Request{
				PostForm: url.Values{
					"client_id":     {"1234"},
					"client_secret": {"foobar"},
					"scope":         {"foo bar"},
				},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), gomock.Any()).Return(&DefaultOpenIDConnectClient{
					DefaultClient: &DefaultClient{
						ID:         "1234",
						Secret:     []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
						GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
						Scopes:     []string{"foo", "bar"},
					},
					TokenEndpointAuthMethod: "client_secret_post",
				}, nil)
			},
			expect: &DeviceAuthorizeRequest{
				Request: Request{
					Client: &DefaultClient{
						Scopes: []string{"foo", "bar"},
					},
					RequestedScope: []string{"foo", "bar"},
				},
			},
		},
		/* should fail because doesn't have proper grant */
		{
			desc: "should pass",
			conf: &Fosite{Store: store, Config: &mockConfig{Config: config, AuthenticateClient: false}},
			r: &http.Request{
				PostForm: url.Values{
					"client_id": {"1234"},
					"scope":     {"foo bar"},
				},
			},
			mock: func() {
				store.EXPECT().GetClient(gomock.Any(), "1234").Return(&DefaultClient{
					Scopes: []string{"foo", "bar"},
				}, nil)
			},
			expectedError: ErrInvalidGrant,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			store = NewMockStorage(ctrl)
			defer ctrl.Finish()

			c.mock()
			if c.r == nil {
				c.r = &http.Request{Header: http.Header{}}
			}

			c.conf.Store = store
			ar, err := c.conf.NewDeviceAuthorizeRequest(context.Background(), c.r)
			if c.expectedError != nil {
				assert.EqualError(t, err, c.expectedError.Error())
				if len(c.ErrorHint) > 0 {
					var rfcerr *RFC6749Error
					assert.ErrorAs(t, err, &rfcerr)
					assert.Equal(t, c.ErrorHint, rfcerr.HintField)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, ar.GetRequestedAt())
			}
		})
	}
}

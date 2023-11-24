// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	. "github.com/ory/fosite/handler/rfc8628"
	"github.com/ory/fosite/storage"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserAuthorizeHandler_PopulateRFC8623UserAuthorizeEndpointResponse(t *testing.T) {
	type fields struct {
		Storage  RFC8628CodeStorage
		Strategy RFC8628CodeStrategy
		Config   interface {
			fosite.DeviceAuthorizeConfigProvider
		}
	}
	type args struct {
		ctx    context.Context
		req    fosite.DeviceAuthorizeRequester
		resp   fosite.RFC8623UserAuthorizeResponder
		status fosite.DeviceAuthorizeStatus
	}

	defaultSetupFunc := func(t *testing.T, dar fosite.DeviceAuthorizeRequester, f *fields, a *args) {
		dar.SetSession(openid.NewDefaultSession())
		dar.GetSession().SetExpiresAt(fosite.UserCode,
			time.Now().UTC().Add(
				f.Config.GetDeviceAndUserCodeLifespan(a.ctx)).Round(time.Second))
		code, sig, err := f.Strategy.GenerateUserCode(a.ctx)
		require.NoError(t, err)
		dar.SetUserCodeSignature(sig)
		err = f.Storage.CreateUserCodeSession(a.ctx, sig, dar)
		require.NoError(t, err)

		dar.GetRequestForm().Set("user_code", code)
		dar.SetStatus(a.status)
	}

	defaultCheckFunc := func(t *testing.T, duvr fosite.RFC8623UserAuthorizeResponder, a *args) {
		assert.NotEmpty(t, duvr)
		assert.Equal(t, fosite.DeviceAuthorizeStatusToString(a.status), duvr.GetStatus())
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		setup   func(t *testing.T, dar fosite.DeviceAuthorizeRequester, f *fields, a *args)
		check   func(t *testing.T, duvr fosite.RFC8623UserAuthorizeResponder, a *args)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "approved",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: &hmacshaStrategy,
				Config: &fosite.Config{
					DeviceAndUserCodeLifespan:      time.Minute * 10,
					DeviceAuthTokenPollingInterval: time.Second * 10,
					RFC8623UserVerificationURL:     "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx:    context.TODO(),
				req:    fosite.NewDeviceAuthorizeRequest(),
				resp:   fosite.NewRFC8623UserAuthorizeResponse(),
				status: fosite.DeviceAuthorizeStatusApproved,
			},
			setup: defaultSetupFunc,
			check: defaultCheckFunc,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.NoError(t, err)
				return err == nil
			},
		},
		{
			name: "denied",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: &hmacshaStrategy,
				Config: &fosite.Config{
					DeviceAndUserCodeLifespan:      time.Minute * 10,
					DeviceAuthTokenPollingInterval: time.Second * 10,
					RFC8623UserVerificationURL:     "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx:    context.TODO(),
				req:    fosite.NewDeviceAuthorizeRequest(),
				resp:   fosite.NewRFC8623UserAuthorizeResponse(),
				status: fosite.DeviceAuthorizeStatusDenied,
			},
			setup: defaultSetupFunc,
			check: defaultCheckFunc,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.NoError(t, err)
				return err == nil
			},
		},
		{
			name: "new",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: &hmacshaStrategy,
				Config: &fosite.Config{
					DeviceAndUserCodeLifespan:      time.Minute * 10,
					DeviceAuthTokenPollingInterval: time.Second * 10,
					RFC8623UserVerificationURL:     "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx:    context.TODO(),
				req:    fosite.NewDeviceAuthorizeRequest(),
				resp:   fosite.NewRFC8623UserAuthorizeResponse(),
				status: fosite.DeviceAuthorizeStatusNew,
			},
			setup: defaultSetupFunc,
			check: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.ErrorIs(t, err, fosite.ErrInvalidRequest)
				return errors.Is(err, fosite.ErrInvalidRequest)
			},
		},
		{
			name: "invalid",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: &hmacshaStrategy,
				Config: &fosite.Config{
					DeviceAndUserCodeLifespan:      time.Minute * 10,
					DeviceAuthTokenPollingInterval: time.Second * 10,
					RFC8623UserVerificationURL:     "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx:    context.TODO(),
				req:    fosite.NewDeviceAuthorizeRequest(),
				resp:   fosite.NewRFC8623UserAuthorizeResponse(),
				status: 1234,
			},
			setup: defaultSetupFunc,
			check: nil,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.ErrorIs(t, err, fosite.ErrInvalidRequest)
				return errors.Is(err, fosite.ErrInvalidRequest)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &UserAuthorizeHandler{
				Storage:  tt.fields.Storage,
				Strategy: tt.fields.Strategy,
				Config:   tt.fields.Config,
			}
			if tt.setup != nil {
				tt.setup(t, tt.args.req, &tt.fields, &tt.args)
			}
			if tt.wantErr != nil {
				tt.wantErr(t, d.PopulateRFC8623UserAuthorizeEndpointResponse(tt.args.ctx, tt.args.req, tt.args.resp),
					fmt.Sprintf("PopulateRFC8623UserAuthorizeEndpointResponse(%v, %v, %v)",
						tt.args.ctx, tt.args.req, tt.args.resp))
			}
			if tt.check != nil {
				tt.check(t, tt.args.resp, &tt.args)
			}
		})
	}
}

func TestUserAuthorizeHandler_PopulateRFC8623UserAuthorizeEndpointResponse_HandleRFC8623UserAuthorizeEndpointRequest(t *testing.T) {
	type fields struct {
		Storage  RFC8628CodeStorage
		Strategy RFC8628CodeStrategy
		Config   interface {
			fosite.DeviceAuthorizeConfigProvider
		}
	}
	type args struct {
		ctx    context.Context
		req    fosite.DeviceAuthorizeRequester
		status fosite.DeviceAuthorizeStatus
	}

	NewDeviceAuthorizeRequest := func(grantTypes []string) *fosite.DeviceAuthorizeRequest {
		req := &fosite.DeviceAuthorizeRequest{
			Request: fosite.Request{
				Client: &fosite.DefaultClient{
					GrantTypes: grantTypes,
				},
				RequestedScope:    fosite.Arguments{},
				RequestedAudience: fosite.Arguments{},
				GrantedAudience:   fosite.Arguments{},
				GrantedScope:      fosite.Arguments{},
				Form:              url.Values{},
				RequestedAt:       time.Now().UTC(),
			},
		}

		return req
	}

	defaultSetupFunc := func(t *testing.T, dar fosite.DeviceAuthorizeRequester, f *fields, a *args) {
		dar.SetSession(openid.NewDefaultSession())
		dar.GetSession().SetExpiresAt(fosite.UserCode,
			time.Now().UTC().Add(
				f.Config.GetDeviceAndUserCodeLifespan(a.ctx)).Round(time.Second))
		code, sig, err := f.Strategy.GenerateUserCode(a.ctx)
		require.NoError(t, err)
		dar.SetUserCodeSignature(sig)
		err = f.Storage.CreateUserCodeSession(a.ctx, sig, dar)
		require.NoError(t, err)

		dar.GetRequestForm().Set("user_code", code)
		dar.SetStatus(a.status)
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		setup   func(t *testing.T, dar fosite.DeviceAuthorizeRequester, f *fields, a *args)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "success",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: &hmacshaStrategy,
				Config: &fosite.Config{
					DeviceAndUserCodeLifespan:      time.Minute * 10,
					DeviceAuthTokenPollingInterval: time.Second * 10,
					RFC8623UserVerificationURL:     "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx: context.TODO(),
				req: NewDeviceAuthorizeRequest(
					[]string{
						string(fosite.GrantTypeDeviceCode),
						string(fosite.GrantTypeImplicit),
						string(fosite.GrantTypePassword),
						string(fosite.GrantTypeClientCredentials),
					}),
				status: fosite.DeviceAuthorizeStatusNew,
			},
			setup: defaultSetupFunc,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.NoError(t, err)
				return err == nil
			},
		},
		{
			name: "invalid client grant types",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: &hmacshaStrategy,
				Config: &fosite.Config{
					DeviceAndUserCodeLifespan:      time.Minute * 10,
					DeviceAuthTokenPollingInterval: time.Second * 10,
					RFC8623UserVerificationURL:     "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx: context.TODO(),
				req: NewDeviceAuthorizeRequest(
					[]string{
						string(fosite.GrantTypeImplicit),
						string(fosite.GrantTypePassword),
						string(fosite.GrantTypeClientCredentials),
					}),
				status: fosite.DeviceAuthorizeStatusNew,
			},
			setup: defaultSetupFunc,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.ErrorIs(t, err, fosite.ErrInvalidGrant)
				return errors.Is(err, fosite.ErrInvalidGrant)
			},
		},
		{
			name: "invalid request no user_code in form",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: &hmacshaStrategy,
				Config: &fosite.Config{
					DeviceAndUserCodeLifespan:      time.Minute * 10,
					DeviceAuthTokenPollingInterval: time.Second * 10,
					RFC8623UserVerificationURL:     "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx: context.TODO(),
				req: NewDeviceAuthorizeRequest(
					[]string{
						string(fosite.GrantTypeDeviceCode),
						string(fosite.GrantTypeImplicit),
						string(fosite.GrantTypePassword),
						string(fosite.GrantTypeClientCredentials),
					}),
				status: fosite.DeviceAuthorizeStatusApproved,
			},
			setup: func(t *testing.T, dar fosite.DeviceAuthorizeRequester, f *fields, a *args) {
				defaultSetupFunc(t, dar, f, a)
				dar.GetRequestForm().Del("user_code")
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.ErrorIs(t, err, fosite.ErrInvalidRequest)
				return errors.Is(err, fosite.ErrInvalidRequest)
			},
		},
		{
			name: "invalid request no user code session",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: &hmacshaStrategy,
				Config: &fosite.Config{
					DeviceAndUserCodeLifespan:      time.Minute * 10,
					DeviceAuthTokenPollingInterval: time.Second * 10,
					RFC8623UserVerificationURL:     "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx: context.TODO(),
				req: NewDeviceAuthorizeRequest(
					[]string{
						string(fosite.GrantTypeDeviceCode),
						string(fosite.GrantTypeImplicit),
						string(fosite.GrantTypePassword),
						string(fosite.GrantTypeClientCredentials),
					}),
				status: fosite.DeviceAuthorizeStatusApproved,
			},
			setup: func(t *testing.T, dar fosite.DeviceAuthorizeRequester, f *fields, a *args) {
				dar.SetSession(openid.NewDefaultSession())
				dar.GetSession().SetExpiresAt(fosite.UserCode,
					time.Now().UTC().Add(
						f.Config.GetDeviceAndUserCodeLifespan(a.ctx)).Round(time.Second))
				code, sig, err := f.Strategy.GenerateUserCode(a.ctx)
				require.NoError(t, err)
				dar.SetUserCodeSignature(sig)
				dar.GetRequestForm().Set("user_code", code)
				dar.SetStatus(a.status)
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.ErrorIs(t, err, fosite.ErrInvalidGrant)
				return errors.Is(err, fosite.ErrInvalidGrant)
			},
		},
		{
			name: "invalid request user code expired",
			fields: fields{
				Storage:  storage.NewMemoryStore(),
				Strategy: &hmacshaStrategy,
				Config: &fosite.Config{
					DeviceAndUserCodeLifespan:      time.Minute * 10,
					DeviceAuthTokenPollingInterval: time.Second * 10,
					RFC8623UserVerificationURL:     "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx: context.TODO(),
				req: NewDeviceAuthorizeRequest(
					[]string{
						string(fosite.GrantTypeDeviceCode),
						string(fosite.GrantTypeImplicit),
						string(fosite.GrantTypePassword),
						string(fosite.GrantTypeClientCredentials),
					}),
				status: fosite.DeviceAuthorizeStatusApproved,
			},
			setup: func(t *testing.T, dar fosite.DeviceAuthorizeRequester, f *fields, a *args) {
				dar.SetSession(openid.NewDefaultSession())
				dar.GetSession().SetExpiresAt(fosite.UserCode,
					time.Now().UTC().Add(time.Duration(-1)*
						f.Config.GetDeviceAndUserCodeLifespan(a.ctx)).Round(time.Second))
				code, sig, err := f.Strategy.GenerateUserCode(a.ctx)
				require.NoError(t, err)
				dar.SetUserCodeSignature(sig)
				err = f.Storage.CreateUserCodeSession(a.ctx, sig, dar)
				require.NoError(t, err)

				dar.GetRequestForm().Set("user_code", code)
				dar.SetStatus(a.status)
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				assert.ErrorIs(t, err, fosite.ErrInvalidGrant)
				return errors.Is(err, fosite.ErrInvalidGrant)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &UserAuthorizeHandler{
				Storage:  tt.fields.Storage,
				Strategy: tt.fields.Strategy,
				Config:   tt.fields.Config,
			}
			if tt.setup != nil {
				tt.setup(t, tt.args.req, &tt.fields, &tt.args)
			}
			if tt.wantErr != nil {
				tt.wantErr(t, d.HandleRFC8623UserAuthorizeEndpointRequest(tt.args.ctx, tt.args.req),
					fmt.Sprintf("HandleRFC8623UserAuthorizeEndpointRequest(%v, %v)", tt.args.ctx, tt.args.req))
			}
		})
	}
}

// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628_test

import (
	"context"
	"fmt"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	. "github.com/ory/fosite/handler/rfc8628"
	"github.com/ory/fosite/storage"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
	"time"
)

func TestDeviceUserVerificationHandler_HandleDeviceUserVerificationEndpointRequest(t *testing.T) {
	type fields struct {
		Storage  RFC8628CodeStorage
		Strategy RFC8628CodeStrategy
		Config   interface {
			fosite.DeviceAuthorizationProvider
			fosite.DeviceAndUserCodeLifespanProvider
		}
	}
	type args struct {
		ctx    context.Context
		req    fosite.DeviceAuthorizationRequester
		resp   fosite.DeviceUserVerificationResponder
		status fosite.DeviceAuthorizationStatus
	}

	defaultSetupFunc := func(t *testing.T, dar fosite.DeviceAuthorizationRequester, f *fields, a *args) {
		dar.SetSession(&DefaultSession{
			DefaultSession: openid.NewDefaultSession(),
		})
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

	defaultCheckFunc := func(t *testing.T, duvr fosite.DeviceUserVerificationResponder, a *args) {
		assert.NotEmpty(t, duvr)
		assert.Equal(t, fosite.DeviceAuthorizationStatusToString(a.status), duvr.GetStatus())
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		setup   func(t *testing.T, dar fosite.DeviceAuthorizationRequester, f *fields, a *args)
		check   func(t *testing.T, duvr fosite.DeviceUserVerificationResponder, a *args)
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
					DeviceVerificationURL:          "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx:    context.TODO(),
				req:    fosite.NewDeviceAuthorizationRequest(),
				resp:   fosite.NewDeviceUserVerificationResponse(),
				status: fosite.DeviceAuthorizationStatusApproved,
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
					DeviceVerificationURL:          "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx:    context.TODO(),
				req:    fosite.NewDeviceAuthorizationRequest(),
				resp:   fosite.NewDeviceUserVerificationResponse(),
				status: fosite.DeviceAuthorizationStatusDenied,
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
					DeviceVerificationURL:          "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx:    context.TODO(),
				req:    fosite.NewDeviceAuthorizationRequest(),
				resp:   fosite.NewDeviceUserVerificationResponse(),
				status: fosite.DeviceAuthorizationStatusNew,
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
					DeviceVerificationURL:          "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx:    context.TODO(),
				req:    fosite.NewDeviceAuthorizationRequest(),
				resp:   fosite.NewDeviceUserVerificationResponse(),
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
			d := &DeviceUserVerificationHandler{
				Storage:  tt.fields.Storage,
				Strategy: tt.fields.Strategy,
				Config:   tt.fields.Config,
			}
			if tt.setup != nil {
				tt.setup(t, tt.args.req, &tt.fields, &tt.args)
			}
			if tt.wantErr != nil {
				tt.wantErr(t, d.HandleDeviceUserVerificationEndpointRequest(tt.args.ctx, tt.args.req, tt.args.resp),
					fmt.Sprintf("HandleDeviceUserVerificationEndpointRequest(%v, %v, %v)",
						tt.args.ctx, tt.args.req, tt.args.resp))
			}
			if tt.check != nil {
				tt.check(t, tt.args.resp, &tt.args)
			}
		})
	}
}

func TestDeviceUserVerificationHandler_HandleDeviceUserVerificationEndpointRequest_ValidateRequest(t *testing.T) {
	type fields struct {
		Storage  RFC8628CodeStorage
		Strategy RFC8628CodeStrategy
		Config   interface {
			fosite.DeviceAuthorizationProvider
			fosite.DeviceAndUserCodeLifespanProvider
		}
	}
	type args struct {
		ctx    context.Context
		req    fosite.DeviceAuthorizationRequester
		status fosite.DeviceAuthorizationStatus
	}

	newDeviceAuthorizationRequest := func(grantTypes []string) *fosite.DeviceAuthorizationRequest {
		req := &fosite.DeviceAuthorizationRequest{
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

	defaultSetupFunc := func(t *testing.T, dar fosite.DeviceAuthorizationRequester, f *fields, a *args) {
		dar.SetSession(&DefaultSession{
			DefaultSession: openid.NewDefaultSession(),
		})
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
		setup   func(t *testing.T, dar fosite.DeviceAuthorizationRequester, f *fields, a *args)
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
					DeviceVerificationURL:          "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx: context.TODO(),
				req: newDeviceAuthorizationRequest(
					[]string{
						string(fosite.GrantTypeDeviceCode),
						string(fosite.GrantTypeImplicit),
						string(fosite.GrantTypePassword),
						string(fosite.GrantTypeClientCredentials),
					}),
				status: fosite.DeviceAuthorizationStatusNew,
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
					DeviceVerificationURL:          "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx: context.TODO(),
				req: newDeviceAuthorizationRequest(
					[]string{
						string(fosite.GrantTypeImplicit),
						string(fosite.GrantTypePassword),
						string(fosite.GrantTypeClientCredentials),
					}),
				status: fosite.DeviceAuthorizationStatusNew,
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
					DeviceVerificationURL:          "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx: context.TODO(),
				req: newDeviceAuthorizationRequest(
					[]string{
						string(fosite.GrantTypeDeviceCode),
						string(fosite.GrantTypeImplicit),
						string(fosite.GrantTypePassword),
						string(fosite.GrantTypeClientCredentials),
					}),
				status: fosite.DeviceAuthorizationStatusApproved,
			},
			setup: func(t *testing.T, dar fosite.DeviceAuthorizationRequester, f *fields, a *args) {
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
					DeviceVerificationURL:          "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx: context.TODO(),
				req: newDeviceAuthorizationRequest(
					[]string{
						string(fosite.GrantTypeDeviceCode),
						string(fosite.GrantTypeImplicit),
						string(fosite.GrantTypePassword),
						string(fosite.GrantTypeClientCredentials),
					}),
				status: fosite.DeviceAuthorizationStatusApproved,
			},
			setup: func(t *testing.T, dar fosite.DeviceAuthorizationRequester, f *fields, a *args) {
				dar.SetSession(&DefaultSession{
					DefaultSession: openid.NewDefaultSession(),
				})
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
					DeviceVerificationURL:          "https://www.test.com",
					AccessTokenLifespan:            time.Hour,
					RefreshTokenLifespan:           time.Hour,
					ScopeStrategy:                  fosite.HierarchicScopeStrategy,
					AudienceMatchingStrategy:       fosite.DefaultAudienceMatchingStrategy,
					RefreshTokenScopes:             []string{"offline"},
				},
			},
			args: args{
				ctx: context.TODO(),
				req: newDeviceAuthorizationRequest(
					[]string{
						string(fosite.GrantTypeDeviceCode),
						string(fosite.GrantTypeImplicit),
						string(fosite.GrantTypePassword),
						string(fosite.GrantTypeClientCredentials),
					}),
				status: fosite.DeviceAuthorizationStatusApproved,
			},
			setup: func(t *testing.T, dar fosite.DeviceAuthorizationRequester, f *fields, a *args) {
				dar.SetSession(&DefaultSession{
					DefaultSession: openid.NewDefaultSession(),
				})
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
			d := &DeviceUserVerificationHandler{
				Storage:  tt.fields.Storage,
				Strategy: tt.fields.Strategy,
				Config:   tt.fields.Config,
			}
			if tt.setup != nil {
				tt.setup(t, tt.args.req, &tt.fields, &tt.args)
			}
			if tt.wantErr != nil {
				tt.wantErr(t, d.ValidateRequest(tt.args.ctx, tt.args.req),
					fmt.Sprintf("ValidateRequest(%v, %v)", tt.args.ctx, tt.args.req))
			}
		})
	}
}

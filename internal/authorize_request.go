// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/ory/fosite (interfaces: AuthorizeRequester)

// Package internal is a generated GoMock package.
package internal

import (
	url "net/url"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"

	fosite "github.com/ory/fosite"
)

// MockAuthorizeRequester is a mock of AuthorizeRequester interface.
type MockAuthorizeRequester struct {
	ctrl     *gomock.Controller
	recorder *MockAuthorizeRequesterMockRecorder
}

// MockAuthorizeRequesterMockRecorder is the mock recorder for MockAuthorizeRequester.
type MockAuthorizeRequesterMockRecorder struct {
	mock *MockAuthorizeRequester
}

// NewMockAuthorizeRequester creates a new mock instance.
func NewMockAuthorizeRequester(ctrl *gomock.Controller) *MockAuthorizeRequester {
	mock := &MockAuthorizeRequester{ctrl: ctrl}
	mock.recorder = &MockAuthorizeRequesterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthorizeRequester) EXPECT() *MockAuthorizeRequesterMockRecorder {
	return m.recorder
}

// AppendRequestedScope mocks base method.
func (m *MockAuthorizeRequester) AppendRequestedScope(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "AppendRequestedScope", arg0)
}

// AppendRequestedScope indicates an expected call of AppendRequestedScope.
func (mr *MockAuthorizeRequesterMockRecorder) AppendRequestedScope(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AppendRequestedScope", reflect.TypeOf((*MockAuthorizeRequester)(nil).AppendRequestedScope), arg0)
}

// DidHandleAllResponseTypes mocks base method.
func (m *MockAuthorizeRequester) DidHandleAllResponseTypes() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DidHandleAllResponseTypes")
	ret0, _ := ret[0].(bool)
	return ret0
}

// DidHandleAllResponseTypes indicates an expected call of DidHandleAllResponseTypes.
func (mr *MockAuthorizeRequesterMockRecorder) DidHandleAllResponseTypes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DidHandleAllResponseTypes", reflect.TypeOf((*MockAuthorizeRequester)(nil).DidHandleAllResponseTypes))
}

// GetClient mocks base method.
func (m *MockAuthorizeRequester) GetClient() fosite.Client {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetClient")
	ret0, _ := ret[0].(fosite.Client)
	return ret0
}

// GetClient indicates an expected call of GetClient.
func (mr *MockAuthorizeRequesterMockRecorder) GetClient() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetClient", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetClient))
}

// GetDefaultResponseMode mocks base method.
func (m *MockAuthorizeRequester) GetDefaultResponseMode() fosite.ResponseModeType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetDefaultResponseMode")
	ret0, _ := ret[0].(fosite.ResponseModeType)
	return ret0
}

// GetDefaultResponseMode indicates an expected call of GetDefaultResponseMode.
func (mr *MockAuthorizeRequesterMockRecorder) GetDefaultResponseMode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetDefaultResponseMode", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetDefaultResponseMode))
}

// GetGrantedAudience mocks base method.
func (m *MockAuthorizeRequester) GetGrantedAudience() fosite.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGrantedAudience")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

// GetGrantedAudience indicates an expected call of GetGrantedAudience.
func (mr *MockAuthorizeRequesterMockRecorder) GetGrantedAudience() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGrantedAudience", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetGrantedAudience))
}

// GetGrantedScopes mocks base method.
func (m *MockAuthorizeRequester) GetGrantedScopes() fosite.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetGrantedScopes")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

// GetGrantedScopes indicates an expected call of GetGrantedScopes.
func (mr *MockAuthorizeRequesterMockRecorder) GetGrantedScopes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetGrantedScopes", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetGrantedScopes))
}

// GetID mocks base method.
func (m *MockAuthorizeRequester) GetID() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetID")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetID indicates an expected call of GetID.
func (mr *MockAuthorizeRequesterMockRecorder) GetID() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetID", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetID))
}

// GetRedirectURI mocks base method.
func (m *MockAuthorizeRequester) GetRedirectURI() *url.URL {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRedirectURI")
	ret0, _ := ret[0].(*url.URL)
	return ret0
}

// GetRedirectURI indicates an expected call of GetRedirectURI.
func (mr *MockAuthorizeRequesterMockRecorder) GetRedirectURI() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRedirectURI", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetRedirectURI))
}

// GetRequestForm mocks base method.
func (m *MockAuthorizeRequester) GetRequestForm() url.Values {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestForm")
	ret0, _ := ret[0].(url.Values)
	return ret0
}

// GetRequestForm indicates an expected call of GetRequestForm.
func (mr *MockAuthorizeRequesterMockRecorder) GetRequestForm() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestForm", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetRequestForm))
}

// GetRequestedAt mocks base method.
func (m *MockAuthorizeRequester) GetRequestedAt() time.Time {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestedAt")
	ret0, _ := ret[0].(time.Time)
	return ret0
}

// GetRequestedAt indicates an expected call of GetRequestedAt.
func (mr *MockAuthorizeRequesterMockRecorder) GetRequestedAt() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestedAt", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetRequestedAt))
}

// GetRequestedAudience mocks base method.
func (m *MockAuthorizeRequester) GetRequestedAudience() fosite.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestedAudience")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

// GetRequestedAudience indicates an expected call of GetRequestedAudience.
func (mr *MockAuthorizeRequesterMockRecorder) GetRequestedAudience() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestedAudience", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetRequestedAudience))
}

// GetRequestedScopes mocks base method.
func (m *MockAuthorizeRequester) GetRequestedScopes() fosite.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestedScopes")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

// GetRequestedScopes indicates an expected call of GetRequestedScopes.
func (mr *MockAuthorizeRequesterMockRecorder) GetRequestedScopes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestedScopes", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetRequestedScopes))
}

// GetResponseMode mocks base method.
func (m *MockAuthorizeRequester) GetResponseMode() fosite.ResponseModeType {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetResponseMode")
	ret0, _ := ret[0].(fosite.ResponseModeType)
	return ret0
}

// GetResponseMode indicates an expected call of GetResponseMode.
func (mr *MockAuthorizeRequesterMockRecorder) GetResponseMode() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetResponseMode", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetResponseMode))
}

// GetResponseTypes mocks base method.
func (m *MockAuthorizeRequester) GetResponseTypes() fosite.Arguments {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetResponseTypes")
	ret0, _ := ret[0].(fosite.Arguments)
	return ret0
}

// GetResponseTypes indicates an expected call of GetResponseTypes.
func (mr *MockAuthorizeRequesterMockRecorder) GetResponseTypes() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetResponseTypes", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetResponseTypes))
}

// GetSession mocks base method.
func (m *MockAuthorizeRequester) GetSession() fosite.Session {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetSession")
	ret0, _ := ret[0].(fosite.Session)
	return ret0
}

// GetSession indicates an expected call of GetSession.
func (mr *MockAuthorizeRequesterMockRecorder) GetSession() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetSession", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetSession))
}

// GetState mocks base method.
func (m *MockAuthorizeRequester) GetState() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetState")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetState indicates an expected call of GetState.
func (mr *MockAuthorizeRequesterMockRecorder) GetState() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetState", reflect.TypeOf((*MockAuthorizeRequester)(nil).GetState))
}

// GrantAudience mocks base method.
func (m *MockAuthorizeRequester) GrantAudience(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GrantAudience", arg0)
}

// GrantAudience indicates an expected call of GrantAudience.
func (mr *MockAuthorizeRequesterMockRecorder) GrantAudience(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrantAudience", reflect.TypeOf((*MockAuthorizeRequester)(nil).GrantAudience), arg0)
}

// GrantScope mocks base method.
func (m *MockAuthorizeRequester) GrantScope(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GrantScope", arg0)
}

// GrantScope indicates an expected call of GrantScope.
func (mr *MockAuthorizeRequesterMockRecorder) GrantScope(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GrantScope", reflect.TypeOf((*MockAuthorizeRequester)(nil).GrantScope), arg0)
}

// IsRedirectURIValid mocks base method.
func (m *MockAuthorizeRequester) IsRedirectURIValid() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsRedirectURIValid")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsRedirectURIValid indicates an expected call of IsRedirectURIValid.
func (mr *MockAuthorizeRequesterMockRecorder) IsRedirectURIValid() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsRedirectURIValid", reflect.TypeOf((*MockAuthorizeRequester)(nil).IsRedirectURIValid))
}

// Merge mocks base method.
func (m *MockAuthorizeRequester) Merge(arg0 fosite.Requester) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Merge", arg0)
}

// Merge indicates an expected call of Merge.
func (mr *MockAuthorizeRequesterMockRecorder) Merge(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Merge", reflect.TypeOf((*MockAuthorizeRequester)(nil).Merge), arg0)
}

// Sanitize mocks base method.
func (m *MockAuthorizeRequester) Sanitize(arg0 []string) fosite.Requester {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sanitize", arg0)
	ret0, _ := ret[0].(fosite.Requester)
	return ret0
}

// Sanitize indicates an expected call of Sanitize.
func (mr *MockAuthorizeRequesterMockRecorder) Sanitize(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sanitize", reflect.TypeOf((*MockAuthorizeRequester)(nil).Sanitize), arg0)
}

// SetDefaultResponseMode mocks base method.
func (m *MockAuthorizeRequester) SetDefaultResponseMode(arg0 fosite.ResponseModeType) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetDefaultResponseMode", arg0)
}

// SetDefaultResponseMode indicates an expected call of SetDefaultResponseMode.
func (mr *MockAuthorizeRequesterMockRecorder) SetDefaultResponseMode(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetDefaultResponseMode", reflect.TypeOf((*MockAuthorizeRequester)(nil).SetDefaultResponseMode), arg0)
}

// SetID mocks base method.
func (m *MockAuthorizeRequester) SetID(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetID", arg0)
}

// SetID indicates an expected call of SetID.
func (mr *MockAuthorizeRequesterMockRecorder) SetID(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetID", reflect.TypeOf((*MockAuthorizeRequester)(nil).SetID), arg0)
}

// SetRequestedAudience mocks base method.
func (m *MockAuthorizeRequester) SetRequestedAudience(arg0 fosite.Arguments) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetRequestedAudience", arg0)
}

// SetRequestedAudience indicates an expected call of SetRequestedAudience.
func (mr *MockAuthorizeRequesterMockRecorder) SetRequestedAudience(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetRequestedAudience", reflect.TypeOf((*MockAuthorizeRequester)(nil).SetRequestedAudience), arg0)
}

// SetRequestedScopes mocks base method.
func (m *MockAuthorizeRequester) SetRequestedScopes(arg0 fosite.Arguments) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetRequestedScopes", arg0)
}

// SetRequestedScopes indicates an expected call of SetRequestedScopes.
func (mr *MockAuthorizeRequesterMockRecorder) SetRequestedScopes(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetRequestedScopes", reflect.TypeOf((*MockAuthorizeRequester)(nil).SetRequestedScopes), arg0)
}

// SetResponseTypeHandled mocks base method.
func (m *MockAuthorizeRequester) SetResponseTypeHandled(arg0 string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetResponseTypeHandled", arg0)
}

// SetResponseTypeHandled indicates an expected call of SetResponseTypeHandled.
func (mr *MockAuthorizeRequesterMockRecorder) SetResponseTypeHandled(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetResponseTypeHandled", reflect.TypeOf((*MockAuthorizeRequester)(nil).SetResponseTypeHandled), arg0)
}

// SetSession mocks base method.
func (m *MockAuthorizeRequester) SetSession(arg0 fosite.Session) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetSession", arg0)
}

// SetSession indicates an expected call of SetSession.
func (mr *MockAuthorizeRequesterMockRecorder) SetSession(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetSession", reflect.TypeOf((*MockAuthorizeRequester)(nil).SetSession), arg0)
}

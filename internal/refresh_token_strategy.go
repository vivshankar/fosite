// Automatically generated by MockGen. DO NOT EDIT!
// Source: github.com/ory-am/fosite/handler/oauth2 (interfaces: RefreshTokenStrategy)

package internal

import (
	gomock "github.com/golang/mock/gomock"
	fosite "github.com/ory/fosite"
	context "context"
)

// Mock of RefreshTokenStrategy interface
type MockRefreshTokenStrategy struct {
	ctrl     *gomock.Controller
	recorder *_MockRefreshTokenStrategyRecorder
}

// Recorder for MockRefreshTokenStrategy (not exported)
type _MockRefreshTokenStrategyRecorder struct {
	mock *MockRefreshTokenStrategy
}

func NewMockRefreshTokenStrategy(ctrl *gomock.Controller) *MockRefreshTokenStrategy {
	mock := &MockRefreshTokenStrategy{ctrl: ctrl}
	mock.recorder = &_MockRefreshTokenStrategyRecorder{mock}
	return mock
}

func (_m *MockRefreshTokenStrategy) EXPECT() *_MockRefreshTokenStrategyRecorder {
	return _m.recorder
}

func (_m *MockRefreshTokenStrategy) GenerateRefreshToken(_param0 context.Context, _param1 fosite.Requester) (string, string, error) {
	ret := _m.ctrl.Call(_m, "GenerateRefreshToken", _param0, _param1)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

func (_mr *_MockRefreshTokenStrategyRecorder) GenerateRefreshToken(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GenerateRefreshToken", arg0, arg1)
}

func (_m *MockRefreshTokenStrategy) RefreshTokenSignature(_param0 string) string {
	ret := _m.ctrl.Call(_m, "RefreshTokenSignature", _param0)
	ret0, _ := ret[0].(string)
	return ret0
}

func (_mr *_MockRefreshTokenStrategyRecorder) RefreshTokenSignature(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RefreshTokenSignature", arg0)
}

func (_m *MockRefreshTokenStrategy) ValidateRefreshToken(_param0 context.Context, _param1 fosite.Requester, _param2 string) error {
	ret := _m.ctrl.Call(_m, "ValidateRefreshToken", _param0, _param1, _param2)
	ret0, _ := ret[0].(error)
	return ret0
}

func (_mr *_MockRefreshTokenStrategyRecorder) ValidateRefreshToken(arg0, arg1, arg2 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ValidateRefreshToken", arg0, arg1, arg2)
}

package fosite_test

import (
	"context"
	"github.com/golang/mock/gomock"
	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFosite_NewDeviceUserVerificationResponse(t *testing.T) {
	ctrl := gomock.NewController(t)
	handlers := []*internal.MockDeviceUserVerificationEndpointHandler{internal.NewMockDeviceUserVerificationEndpointHandler(ctrl)}
	dar := internal.NewMockDeviceAuthorizationRequester(ctrl)
	defer ctrl.Finish()

	ctx := context.Background()
	oauth2 := &Fosite{Config: &Config{DeviceUserVerificationEndpointHandlers: DeviceUserVerificationEndpointHandlers{handlers[0]}}}
	duo := &Fosite{Config: &Config{DeviceUserVerificationEndpointHandlers: DeviceUserVerificationEndpointHandlers{handlers[0], handlers[0]}}}
	fooErr := errors.New("foo")
	for k, c := range []struct {
		isErr     bool
		mock      func()
		expectErr error
	}{
		{
			mock: func() {
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().HandleDeviceUserVerificationEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			isErr: false,
		},
		{
			mock: func() {
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().HandleDeviceUserVerificationEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
		{
			mock: func() {
				oauth2 = duo
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().HandleDeviceUserVerificationEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleDeviceUserVerificationEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			},
			isErr: false,
		},
		{
			mock: func() {
				oauth2 = duo
				dar.EXPECT().SetSession(gomock.Any())
				handlers[0].EXPECT().HandleDeviceUserVerificationEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				handlers[0].EXPECT().HandleDeviceUserVerificationEndpointRequest(gomock.Any(), gomock.Any(), gomock.Any()).Return(fooErr)
			},
			isErr:     true,
			expectErr: fooErr,
		},
	} {
		c.mock()
		responder, err := oauth2.NewDeviceUserVerificationResponse(ctx, dar, new(DefaultSession))
		assert.Equal(t, c.isErr, err != nil, "%d: %s", k, err)
		if err != nil {
			assert.Equal(t, c.expectErr, err, "%d: %s", k, err)
			assert.Nil(t, responder, "%d", k)
		} else {
			assert.NotNil(t, responder, "%d", k)
		}
		t.Logf("Passed test case %d", k)
	}
}

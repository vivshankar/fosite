package fosite_test

import (
	"context"
	"encoding/json"
	. "github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"testing"
)

func TestFosite_WriteDeviceUserVerificationError(t *testing.T) {
	oauth2 := &Fosite{Config: &Config{}}

	rw := httptest.NewRecorder()
	ar := &DeviceAuthorizationRequest{}
	resp := &DeviceUserVerificationResponse{}

	resp.SetStatus(DeviceAuthorizationStatusToString(DeviceAuthorizationStatusApproved))

	oauth2.WriteDeviceUserVerificationResponse(context.Background(), rw, ar, resp)
	wroteDeviceResponse := DeviceUserVerificationResponse{}
	err := wroteDeviceResponse.FromJson(rw.Body)
	require.NoError(t, err)

	assert.Equal(t, resp.GetStatus(), wroteDeviceResponse.GetStatus())
	assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rw.Header().Get("Pragma"))
	assert.Equal(t, "application/json;charset=UTF-8", rw.Header().Get("Content-Type"))
}

func TestFosite_WriteDeviceUserVerificationResponse(t *testing.T) {
	oauth2 := &Fosite{Config: &Config{}}

	rw := httptest.NewRecorder()
	ar := &DeviceAuthorizationRequest{}
	theErr := ErrInvalidGrant.WithDescription("invalid grant message.")

	oauth2.WriteDeviceUserVerificationError(context.Background(), rw, ar, theErr)

	result := map[string]string{}
	err := json.NewDecoder(rw.Body).Decode(&result)
	assert.NoError(t, err)
	assert.Contains(t, result, "error")
	assert.Equal(t, theErr.ErrorField, result["error"])
	assert.Contains(t, result, "error_description")
	assert.Equal(t, theErr.DescriptionField, result["error_description"])
	assert.Equal(t, "no-store", rw.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", rw.Header().Get("Pragma"))
	assert.Equal(t, "application/json;charset=UTF-8", rw.Header().Get("Content-Type"))
}

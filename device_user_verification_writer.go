// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

func (f *Fosite) WriteDeviceUserVerificationResponse(_ context.Context, rw http.ResponseWriter, _ DeviceAuthorizationRequester, responder DeviceUserVerificationResponder) {
	wh := rw.Header()
	rh := responder.GetHeader()
	for k := range rh {
		wh.Set(k, rh.Get(k))
	}

	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	deviceResponse := &DeviceUserVerificationResponse{
		Status: responder.GetStatus(),
	}

	_ = deviceResponse.ToJson(rw)
}

func (f *Fosite) WriteDeviceUserVerificationError(ctx context.Context, rw http.ResponseWriter, req DeviceAuthorizationRequester, err error) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

	sendDebugMessagesToClients := f.Config.GetSendDebugMessagesToClients(ctx)
	rfcerr := ErrorToRFC6749Error(err).WithExposeDebug(sendDebugMessagesToClients).WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(req))

	js, err := json.Marshal(rfcerr)
	if err != nil {
		if f.Config.GetSendDebugMessagesToClients(ctx) {
			errorMessage := EscapeJSONString(err.Error())
			http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
		} else {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
		}
		return
	}

	rw.WriteHeader(rfcerr.CodeField)
	_, _ = rw.Write(js)
}

// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
)

var (
	_ DeviceUserVerificationResponder = (*DeviceUserVerificationResponse)(nil)
)

// DeviceUserVerificationResponse is an implementation of DeviceUserVerificationResponder
type DeviceUserVerificationResponse struct {
	Header     http.Header            `json:"-"`
	Parameters url.Values             `json:"-"`
	Status     string                 `json:"status"`
	Extra      map[string]interface{} `json:"-"`
}

func NewDeviceUserVerificationResponse() *DeviceUserVerificationResponse {
	return &DeviceUserVerificationResponse{
		Header:     http.Header{},
		Parameters: url.Values{},
	}
}

func (d *DeviceUserVerificationResponse) GetHeader() http.Header {
	return d.Header
}

func (d *DeviceUserVerificationResponse) AddHeader(key, value string) {
	d.Header.Add(key, value)
}

func (d *DeviceUserVerificationResponse) GetParameters() url.Values {
	return d.Parameters
}

func (d *DeviceUserVerificationResponse) AddParameter(key, value string) {
	d.Parameters.Add(key, value)
}

func (d *DeviceUserVerificationResponse) GetStatus() string {
	return d.Status
}

func (d *DeviceUserVerificationResponse) SetStatus(status string) {
	d.Status = status
}

func (d *DeviceUserVerificationResponse) ToJson(rw io.Writer) error {
	return json.NewEncoder(rw).Encode(&d)
}

func (d *DeviceUserVerificationResponse) FromJson(r io.Reader) error {
	return json.NewDecoder(r).Decode(&d)
}

func (d *DeviceUserVerificationResponse) SetExtra(key string, value interface{}) {
	d.Extra[key] = value
}

func (d *DeviceUserVerificationResponse) GetExtra(key string) interface{} {
	return d.Extra[key]
}

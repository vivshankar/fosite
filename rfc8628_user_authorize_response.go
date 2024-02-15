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
	_ RFC8628UserAuthorizeResponder = (*RFC8628UserAuthorizeResponse)(nil)
)

// RFC8628UserAuthorizeResponse is an implementation of RFC8628UserAuthorizeResponder
type RFC8628UserAuthorizeResponse struct {
	Header     http.Header            `json:"-"`
	Parameters url.Values             `json:"-"`
	Status     string                 `json:"status"`
	Extra      map[string]interface{} `json:"-"`
}

func NewRFC8628UserAuthorizeResponse() *RFC8628UserAuthorizeResponse {
	return &RFC8628UserAuthorizeResponse{
		Header:     http.Header{},
		Parameters: url.Values{},
		Extra:      map[string]interface{}{},
	}
}

func (d *RFC8628UserAuthorizeResponse) GetHeader() http.Header {
	return d.Header
}

func (d *RFC8628UserAuthorizeResponse) AddHeader(key, value string) {
	d.Header.Add(key, value)
}

func (d *RFC8628UserAuthorizeResponse) GetParameters() url.Values {
	return d.Parameters
}

func (d *RFC8628UserAuthorizeResponse) AddParameter(key, value string) {
	d.Parameters.Add(key, value)
}

func (d *RFC8628UserAuthorizeResponse) GetStatus() string {
	return d.Status
}

func (d *RFC8628UserAuthorizeResponse) SetStatus(status string) {
	d.Status = status
}

func (d *RFC8628UserAuthorizeResponse) ToJson(rw io.Writer) error {
	return json.NewEncoder(rw).Encode(&d)
}

func (d *RFC8628UserAuthorizeResponse) FromJson(r io.Reader) error {
	return json.NewDecoder(r).Decode(&d)
}

func (d *RFC8628UserAuthorizeResponse) SetExtra(key string, value interface{}) {
	d.Extra[key] = value
}

func (d *RFC8628UserAuthorizeResponse) GetExtra(key string) interface{} {
	return d.Extra[key]
}

// ToMap converts the response to a map.
func (d *RFC8628UserAuthorizeResponse) ToMap() map[string]interface{} {
	d.Extra["status"] = d.Status

	return d.Extra
}

// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"time"
)

type DeviceAuthorizationStatus int

const (
	DeviceAuthorizationStatusNew DeviceAuthorizationStatus = iota
	DeviceAuthorizationStatusApproved
	DeviceAuthorizationStatusDenied
)

var (
	_ DeviceAuthorizationRequester = (*DeviceAuthorizationRequest)(nil)
)

// DeviceAuthorizationRequest is an implementation of DeviceAuthorizationRequester
type DeviceAuthorizationRequest struct {
	Request
	DeviceCodeSignature string
	UserCodeSignature   string
	Status              DeviceAuthorizationStatus
	LastChecked         time.Time
}

func NewDeviceAuthorizationRequest() *DeviceAuthorizationRequest {
	return &DeviceAuthorizationRequest{
		Request: *NewRequest(),
	}
}

// SetDeviceCodeSignature set the device code signature
func (d *DeviceAuthorizationRequest) SetDeviceCodeSignature(signature string) {
	d.DeviceCodeSignature = signature
}

// GetDeviceCodeSignature returns the device code signature
func (d *DeviceAuthorizationRequest) GetDeviceCodeSignature() string {
	return d.DeviceCodeSignature
}

// SetUserCodeSignature set the user code signature
func (d *DeviceAuthorizationRequest) SetUserCodeSignature(signature string) {
	d.UserCodeSignature = signature
}

// GetUserCodeSignature returns the user code signature
func (d *DeviceAuthorizationRequest) GetUserCodeSignature() string {
	return d.UserCodeSignature
}

func (d *DeviceAuthorizationRequest) SetStatus(status DeviceAuthorizationStatus) {
	d.Status = status
}

func (d *DeviceAuthorizationRequest) GetStatus() DeviceAuthorizationStatus {
	return d.Status
}

func (d *DeviceAuthorizationRequest) SetLastChecked(lastChecked time.Time) {
	d.LastChecked = lastChecked
}

func (d *DeviceAuthorizationRequest) GetLastChecked() time.Time {
	return d.LastChecked
}

func (d *DeviceAuthorizationRequest) Merge(requester Requester) {
	d.Request.Merge(requester)

	authReq, ok := requester.(*DeviceAuthorizationRequest)
	if ok {
		d.Status = authReq.Status
		d.DeviceCodeSignature = authReq.DeviceCodeSignature
		d.UserCodeSignature = authReq.UserCodeSignature
		d.LastChecked = authReq.LastChecked
	}
}

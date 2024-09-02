// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/ory/x/errorsx"
)

type RFC9396AuthorizationDetailsType struct {
	// Type is the authorization details type that is a mandatory part of the
	// authorization details object prescribed by RFC9396.
	Type string `json:"type,omitempty"`

	// Locations is an array of strings representing the location of the resource or RS.
	// These strings are typically URIs identifying the location of the RS.
	Locations []string `json:"locations,omitempty"`

	// Actions is an array of strings representing the kinds of actions to be taken at the resource.
	Actions []string `json:"actions,omitempty"`

	// Datatypes is an array of strings representing the kinds of data being requested from the resource.
	Datatypes []string `json:"datatypes,omitempty"`

	// Identifier is a string identifier indicating a specific resource available at the API.
	Identifier string `json:"identifier,omitempty"`

	// Privileges is an array of strings representing the types or levels of privilege being requested at the resource.
	Privileges []string `json:"privileges,omitempty"`

	// Extra contains data that is non-prescriptive.
	Extra map[string]interface{} `json:"-"`

	// RFC9396AuthorizationDetailsTypeHandler extends the object with custom equals and validate functions.
	RFC9396AuthorizationDetailsTypeHandler `json:"-"`
}

func (ad *RFC9396AuthorizationDetailsType) Equals(cmp *RFC9396AuthorizationDetailsType) bool {
	return ad.RFC9396AuthorizationDetailsTypeHandler.Equals(ad, cmp)
}

func (ad *RFC9396AuthorizationDetailsType) Validate() error {
	return ad.RFC9396AuthorizationDetailsTypeHandler.Validate(ad)
}

func (ad *RFC9396AuthorizationDetailsType) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	m := map[string]interface{}{}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	ad.Type, _ = m["type"].(string)
	ad.Actions = Map(m).SafeStringSlice("actions", nil)
	ad.Datatypes = Map(m).SafeStringSlice("datatypes", nil)
	ad.Identifier, _ = m["identifier"].(string)
	ad.Locations = Map(m).SafeStringSlice("locations", nil)
	ad.Privileges = Map(m).SafeStringSlice("privileges", nil)

	for k, v := range m {
		if k == "type" || k == "actions" || k == "datatypes" || k == "identifier" || k == "locations" || k == "privileges" {
			continue
		}

		if ad.Extra == nil {
			ad.Extra = map[string]interface{}{}
		}

		ad.Extra[k] = v
	}

	return nil
}

func (ad *RFC9396AuthorizationDetailsType) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"type":       ad.Type,
		"actions":    ad.Actions,
		"datatypes":  ad.Datatypes,
		"identifier": ad.Identifier,
		"locations":  ad.Locations,
		"privileges": ad.Privileges,
	}

	for k, v := range ad.Extra {
		m[k] = v
	}

	return json.Marshal(m)
}

func (ad *RFC9396AuthorizationDetailsType) DecorateWithTypeHandler(ctx context.Context, config RFC9396ConfigProvider) {
	typeHandlers := config.GetAuthorizationDetailTypeHandlers(ctx)
	if typeHandler, ok := typeHandlers[ad.Type]; ok {
		ad.RFC9396AuthorizationDetailsTypeHandler = typeHandler
	} else {
		ad.RFC9396AuthorizationDetailsTypeHandler = &RFC9396DefaultAuthorizationDetailsTypeHandler{}
	}
}

func (ad *RFC9396AuthorizationDetailsType) String() string {
	if ad == nil {
		return "<nil>"
	}

	return fmt.Sprintf("%+v", *ad)
}

type RFC9396AuthorizationDetailsTypeHandler interface {
	Equals(t1, t2 *RFC9396AuthorizationDetailsType) bool

	Validate(t *RFC9396AuthorizationDetailsType) error
}

type RFC9396DefaultAuthorizationDetailsTypeHandler struct{}

// Equals checks if the common properties of the struct match. It ignores the Extra attributes
// because it is not well-formed.
func (h *RFC9396DefaultAuthorizationDetailsTypeHandler) Equals(t1, t2 *RFC9396AuthorizationDetailsType) bool {
	if t1 == nil && t2 == nil {
		return true
	}

	if t1 == nil || t2 == nil {
		return false
	}

	return t1.Type == t2.Type &&
		t1.Identifier == t2.Identifier &&
		slices.Equal(t1.Actions, t2.Actions) &&
		slices.Equal(t1.Datatypes, t2.Datatypes) &&
		slices.Equal(t1.Locations, t2.Locations) &&
		slices.Equal(t1.Privileges, t2.Privileges)
}

// Validate validates the common properties.
func (h *RFC9396DefaultAuthorizationDetailsTypeHandler) Validate(t *RFC9396AuthorizationDetailsType) error {
	if len(t.Type) == 0 {
		return errorsx.WithStack(ErrInvalidAuthorizationDetails.WithHint("Missing 'type' in the authorization details object."))
	}

	return nil
}

// RFC9396AuthorizationDetailsStrategy is a strategy for matching authorization detail types.
// This mirrors ScopeStrategy.
type RFC9396AuthorizationDetailsStrategy func(haystack []string, needle string) bool

func RFC9396ExactAuthorizationDetailsStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		if needle == this {
			return true
		}
	}

	return false
}

type RFC9396Client interface {
	// GetAuthorizationDetailTypes returns the list of authorization detail types supported
	// for the client.
	GetAuthorizationDetailTypes() Arguments
}

type DefaultRFC9396Client struct {
	*DefaultClient
	AuthorizationDetails Arguments
}

// GetAuthorizationDetailTypes returns the list of authorization detail types supported
// for the client.
func (c *DefaultRFC9396Client) GetAuthorizationDetailTypes() Arguments {
	return c.AuthorizationDetails
}

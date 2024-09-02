// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

// Map extends the standard Go map with helper functions
type Map map[string]interface{}

// SafeStringSlice converts a map entry to a string array if possible
func (m Map) SafeStringSlice(key string, def []string) []string {
	if m == nil {
		return def
	}

	mval, ok := m[key]
	if !ok {
		return def
	}

	var result []string
	if sa, ok := mval.([]string); ok {
		result = make([]string, len(sa))
		copy(result, sa)
	} else if ia, ok := mval.([]interface{}); ok {
		for _, val := range ia {
			if s, ok := val.(string); ok {
				result = append(result, s)
			}
		}
		if len(result) == 0 {
			return def
		}
	} else if v, ok := mval.(string); ok {
		result = append(result, v)
	} else {
		return def
	}
	return result
}

// SafeString converts a map entry to a string if possible
func (m Map) SafeString(key string, def string) string {
	if m == nil {
		return def
	}

	mval, ok := m[key]
	if !ok {
		return def
	}

	val, ok := mval.(string)
	if !ok {
		return def
	}

	if val == "" {
		return def
	}

	return val
}

// SafeMap converts a map entry to a map[string]interface{} if possible
func (m Map) SafeMap(key string, def map[string]interface{}) map[string]interface{} {
	if m == nil {
		return def
	}

	mval, ok := m[key]
	if !ok {
		return def
	}

	val, ok := mval.(map[string]interface{})
	if !ok {
		return def
	}

	return val
}

// SafeSlice converts a map entry to a interface{} array if possible
func (m Map) SafeSlice(key string, def []interface{}) []interface{} {
	if m == nil {
		return def
	}

	mval, ok := m[key]
	if !ok {
		return def
	}

	vals, ok := mval.([]interface{})
	if !ok {
		return def
	}

	return vals
}

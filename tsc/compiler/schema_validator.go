package compiler

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// schemaValidator validates a JSON document against a JSON Schema (draft 2020-12).
// It implements the subset of JSON Schema features used by tsc/spec/schema.json:
// type, required, additionalProperties, properties, $ref, $defs, const, pattern,
// enum, if/then, minProperties, minItems, minimum, maximum, uniqueItems,
// propertyNames.
type schemaValidator struct {
	root map[string]interface{}
	defs map[string]interface{}
}

// newSchemaValidator parses schemaJSON and returns a ready-to-use validator.
func newSchemaValidator(schemaJSON []byte) (*schemaValidator, error) {
	var root map[string]interface{}
	if err := json.Unmarshal(schemaJSON, &root); err != nil {
		return nil, fmt.Errorf("invalid schema JSON: %w", err)
	}
	sv := &schemaValidator{root: root}
	if defs, ok := root["$defs"].(map[string]interface{}); ok {
		sv.defs = defs
	}
	return sv, nil
}

// Validate validates doc against the schema root.
// Returns all validation errors found.
func (sv *schemaValidator) Validate(doc map[string]interface{}) []error {
	return sv.validateNode(doc, sv.root, "")
}

func (sv *schemaValidator) validateNode(data interface{}, schema map[string]interface{}, path string) []error {
	var errs []error

	// Resolve $ref before any other checks.
	if ref, ok := schema["$ref"].(string); ok {
		resolved := sv.resolveRef(ref)
		if resolved == nil {
			return append(errs, fmt.Errorf("%s: unresolved $ref %q", path, ref))
		}
		return sv.validateNode(data, resolved, path)
	}

	// type
	if typeVal, ok := schema["type"].(string); ok {
		if err := checkJSONType(data, typeVal, path); err != nil {
			// Can't meaningfully continue type-specific checks.
			return append(errs, err)
		}
	}

	// const
	if constVal, ok := schema["const"]; ok {
		if !jsonDeepEqual(data, constVal) {
			errs = append(errs, fmt.Errorf("%s: must equal %v, got %v", path, constVal, data))
		}
	}

	// enum
	if enumVals, ok := schema["enum"].([]interface{}); ok {
		found := false
		for _, e := range enumVals {
			if jsonDeepEqual(data, e) {
				found = true
				break
			}
		}
		if !found {
			strs := make([]string, len(enumVals))
			for i, e := range enumVals {
				strs[i] = fmt.Sprintf("%v", e)
			}
			errs = append(errs, fmt.Errorf("%s: must be one of [%s], got %v", path, strings.Join(strs, ", "), data))
		}
	}

	// pattern (string)
	if pattern, ok := schema["pattern"].(string); ok {
		if s, ok := data.(string); ok {
			re, err := regexp.Compile(pattern)
			if err == nil && !re.MatchString(s) {
				errs = append(errs, fmt.Errorf("%s: %q does not match pattern %q", path, s, pattern))
			}
		}
	}

	// numeric: minimum / maximum
	if num, ok := toJSONFloat(data); ok {
		if min, ok := schema["minimum"].(float64); ok {
			if num < min {
				errs = append(errs, fmt.Errorf("%s: %v is less than minimum %v", path, num, min))
			}
		}
		if max, ok := schema["maximum"].(float64); ok {
			if num > max {
				errs = append(errs, fmt.Errorf("%s: %v exceeds maximum %v", path, num, max))
			}
		}
	}

	// Object-specific validations.
	if dataMap, ok := data.(map[string]interface{}); ok {
		errs = append(errs, sv.validateObject(dataMap, schema, path)...)
	}

	// Array-specific validations.
	if dataArr, ok := data.([]interface{}); ok {
		errs = append(errs, sv.validateArray(dataArr, schema, path)...)
	}

	return errs
}

func (sv *schemaValidator) validateObject(dataMap map[string]interface{}, schema map[string]interface{}, path string) []error {
	var errs []error

	props, _ := schema["properties"].(map[string]interface{})

	// required
	if required, ok := schema["required"].([]interface{}); ok {
		for _, req := range required {
			key, _ := req.(string)
			if _, exists := dataMap[key]; !exists {
				childPath := childKey(path, key)
				errs = append(errs, fmt.Errorf("%s: missing required field", childPath))
			}
		}
	}

	// minProperties
	if minProps, ok := schema["minProperties"].(float64); ok {
		if len(dataMap) < int(minProps) {
			errs = append(errs, fmt.Errorf("%s: must have at least %d properties, has %d", path, int(minProps), len(dataMap)))
		}
	}

	// additionalProperties
	addlProps, hasAddl := schema["additionalProperties"]
	isAddlFalse := hasAddl && addlProps == false

	// propertyNames with enum — disallow unknown keys.
	var allowedNames map[string]bool
	if propNames, ok := schema["propertyNames"].(map[string]interface{}); ok {
		if enumVals, ok := propNames["enum"].([]interface{}); ok {
			allowedNames = make(map[string]bool, len(enumVals))
			for _, e := range enumVals {
				allowedNames[fmt.Sprintf("%v", e)] = true
			}
		}
	}

	for key, val := range dataMap {
		childPath := childKey(path, key)

		// propertyNames enum check.
		if allowedNames != nil && !allowedNames[key] {
			errs = append(errs, fmt.Errorf("%s: unknown property name %q", path, key))
			continue
		}

		// additionalProperties: false
		if isAddlFalse && props != nil {
			if _, defined := props[key]; !defined {
				errs = append(errs, fmt.Errorf("%s: unknown field %q", path, key))
				continue
			}
		}

		// Recurse into defined property schema.
		if props != nil {
			if propSchema, ok := props[key].(map[string]interface{}); ok {
				errs = append(errs, sv.validateNode(val, propSchema, childPath)...)
			}
		}

		// additionalProperties schema (not false) — validate unrecognised keys.
		if hasAddl && addlProps != false {
			if props == nil || !keyInProps(key, props) {
				if addlSchema, ok := addlProps.(map[string]interface{}); ok {
					errs = append(errs, sv.validateNode(val, addlSchema, childPath)...)
				}
			}
		}
	}

	// if / then
	if ifSchema, ok := schema["if"].(map[string]interface{}); ok {
		if thenSchema, ok := schema["then"].(map[string]interface{}); ok {
			// Condition holds when it produces zero errors.
			if len(sv.validateNode(dataMap, ifSchema, path)) == 0 {
				errs = append(errs, sv.validateNode(dataMap, thenSchema, path)...)
			}
		}
	}

	return errs
}

func (sv *schemaValidator) validateArray(dataArr []interface{}, schema map[string]interface{}, path string) []error {
	var errs []error

	// minItems
	if minItems, ok := schema["minItems"].(float64); ok {
		if len(dataArr) < int(minItems) {
			errs = append(errs, fmt.Errorf("%s: must have at least %d items, has %d", path, int(minItems), len(dataArr)))
		}
	}

	// uniqueItems
	if unique, ok := schema["uniqueItems"].(bool); ok && unique {
		seen := make([]interface{}, 0, len(dataArr))
		for i, item := range dataArr {
			for j, prev := range seen {
				if jsonDeepEqual(item, prev) {
					errs = append(errs, fmt.Errorf("%s[%d]: duplicate of item at index %d", path, i, j))
					break
				}
			}
			seen = append(seen, item)
		}
	}

	// items (single schema applies to every element)
	if itemSchema, ok := schema["items"].(map[string]interface{}); ok {
		for i, item := range dataArr {
			childPath := fmt.Sprintf("%s[%d]", path, i)
			errs = append(errs, sv.validateNode(item, itemSchema, childPath)...)
		}
	}

	return errs
}

func (sv *schemaValidator) resolveRef(ref string) map[string]interface{} {
	const prefix = "#/$defs/"
	if strings.HasPrefix(ref, prefix) {
		name := strings.TrimPrefix(ref, prefix)
		if def, ok := sv.defs[name].(map[string]interface{}); ok {
			return def
		}
	}
	return nil
}

// checkJSONType returns an error if data does not match the expected JSON Schema type name.
func checkJSONType(data interface{}, typeName, path string) error {
	switch typeName {
	case "object":
		if _, ok := data.(map[string]interface{}); !ok {
			return fmt.Errorf("%s: expected object, got %T", path, data)
		}
	case "array":
		if _, ok := data.([]interface{}); !ok {
			return fmt.Errorf("%s: expected array, got %T", path, data)
		}
	case "string":
		if _, ok := data.(string); !ok {
			return fmt.Errorf("%s: expected string, got %T", path, data)
		}
	case "integer":
		if f, ok := data.(float64); ok {
			if f != float64(int64(f)) {
				return fmt.Errorf("%s: expected integer, got float %v", path, f)
			}
		} else {
			return fmt.Errorf("%s: expected integer, got %T", path, data)
		}
	case "boolean":
		if _, ok := data.(bool); !ok {
			return fmt.Errorf("%s: expected boolean, got %T", path, data)
		}
	}
	return nil
}

// jsonDeepEqual compares two JSON-decoded values by re-marshaling them.
func jsonDeepEqual(a, b interface{}) bool {
	aj, errA := json.Marshal(a)
	bj, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(aj) == string(bj)
}

func toJSONFloat(v interface{}) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func childKey(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func keyInProps(key string, props map[string]interface{}) bool {
	_, ok := props[key]
	return ok
}

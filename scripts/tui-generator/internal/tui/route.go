package tui

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func BuildPath(operation Operation, values map[string]any) (string, error) {
	parameters := make(map[string]Parameter)
	for _, parameter := range operation.Parameters {
		if parameter.In == "path" {
			parameters[parameter.Name] = parameter
		}
	}
	var path strings.Builder
	for _, part := range operation.PathParts {
		if part.Parameter == "" {
			path.WriteString(part.Literal)
			continue
		}
		parameter, ok := parameters[part.Parameter]
		if !ok {
			return "", fmt.Errorf("operation %s lacks path parameter %s", operation.ID, part.Parameter)
		}
		value, ok := values[part.Parameter]
		if !ok {
			return "", fmt.Errorf("operation %s requires path parameter %s", operation.ID, part.Parameter)
		}
		serialized, err := serializeSimple(parameter, value)
		if err != nil {
			return "", fmt.Errorf("operation %s path parameter %s: %w", operation.ID, part.Parameter, err)
		}
		path.WriteString(url.PathEscape(serialized))
	}
	return path.String(), nil
}

func BuildQueryAndHeaders(operation Operation, values map[string]any) (url.Values, map[string]string, error) {
	query := make(url.Values)
	headers := make(map[string]string)
	for _, parameter := range operation.Parameters {
		if parameter.In != "query" && parameter.In != "header" {
			continue
		}
		value, present := values[parameter.Name]
		if !present {
			if parameter.Required {
				return nil, nil, fmt.Errorf("operation %s requires %s parameter %s", operation.ID, parameter.In, parameter.Name)
			}
			continue
		}
		if err := validateParameter(parameter, value); err != nil {
			return nil, nil, fmt.Errorf("operation %s %s parameter %s: %w", operation.ID, parameter.In, parameter.Name, err)
		}
		if parameter.In == "header" {
			serialized, err := serializeSimple(parameter, value)
			if err != nil {
				return nil, nil, err
			}
			if strings.ContainsAny(serialized, "\r\n") {
				return nil, nil, fmt.Errorf("header value contains a line break")
			}
			headers[parameter.Name] = serialized
			continue
		}
		if err := serializeQuery(query, parameter, value); err != nil {
			return nil, nil, err
		}
	}
	return query, headers, nil
}

func serializeQuery(result url.Values, parameter Parameter, value any) error {
	switch typed := value.(type) {
	case []any:
		parts := scalarSlice(typed)
		if parameter.Style == "spaceDelimited" {
			result.Set(parameter.Name, strings.Join(parts, " "))
		} else if parameter.Style == "pipeDelimited" {
			result.Set(parameter.Name, strings.Join(parts, "|"))
		} else if parameter.Explode {
			for _, part := range parts {
				result.Add(parameter.Name, part)
			}
		} else {
			result.Set(parameter.Name, strings.Join(parts, ","))
		}
	case map[string]any:
		keys := sortedAnyKeys(typed)
		if parameter.Style == "deepObject" {
			for _, key := range keys {
				result.Set(parameter.Name+"["+key+"]", scalarString(typed[key]))
			}
		} else if parameter.Explode {
			for _, key := range keys {
				result.Set(key, scalarString(typed[key]))
			}
		} else {
			var parts []string
			for _, key := range keys {
				parts = append(parts, key, scalarString(typed[key]))
			}
			result.Set(parameter.Name, strings.Join(parts, ","))
		}
	default:
		result.Set(parameter.Name, scalarString(typed))
	}
	return nil
}

func serializeSimple(parameter Parameter, value any) (string, error) {
	if err := validateParameter(parameter, value); err != nil {
		return "", err
	}
	switch typed := value.(type) {
	case []any:
		return strings.Join(scalarSlice(typed), ","), nil
	case map[string]any:
		keys := sortedAnyKeys(typed)
		var parts []string
		for _, key := range keys {
			if parameter.Explode {
				parts = append(parts, key+"="+scalarString(typed[key]))
			} else {
				parts = append(parts, key, scalarString(typed[key]))
			}
		}
		return strings.Join(parts, ","), nil
	default:
		return scalarString(typed), nil
	}
}

func validateParameter(parameter Parameter, value any) error {
	text := scalarString(value)
	switch parameter.Type {
	case "integer":
		if _, err := strconv.ParseInt(text, 10, 64); err != nil {
			return fmt.Errorf("must be an integer")
		}
	case "number":
		if _, err := strconv.ParseFloat(text, 64); err != nil {
			return fmt.Errorf("must be a number")
		}
	case "boolean":
		if _, err := strconv.ParseBool(text); err != nil {
			return fmt.Errorf("must be a boolean")
		}
	}
	if parameter.Pattern != "" {
		pattern, err := regexp.Compile(parameter.Pattern)
		if err != nil {
			return fmt.Errorf("has invalid schema pattern")
		}
		if !pattern.MatchString(text) {
			return fmt.Errorf("does not match schema pattern")
		}
	}
	return nil
}

func ResolveJSONPointer(value any, pointer string) (any, error) {
	if pointer == "" {
		return value, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("JSON pointer %q must begin with /", pointer)
	}
	current := value
	for _, raw := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		part := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch typed := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = typed[part]
			if !ok {
				return nil, fmt.Errorf("JSON pointer %q is missing %q", pointer, part)
			}
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, fmt.Errorf("JSON pointer %q has invalid array index %q", pointer, part)
			}
			current = typed[index]
		default:
			return nil, fmt.Errorf("JSON pointer %q traverses a scalar", pointer)
		}
	}
	return current, nil
}

func scalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func scalarSlice(values []any) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = scalarString(value)
	}
	return result
}

func sortedAnyKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

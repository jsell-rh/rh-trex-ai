package tui

import (
	"encoding/json"
	"fmt"
)

func renderRaw(value any) (string, error) {
	content, err := json.MarshalIndent(sanitizeRawValue(value), "", "  ")
	if err != nil {
		return "", fmt.Errorf("format raw resource: %w", err)
	}
	return string(content), nil
}

func sanitizeRawValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for _, key := range sortedAnyKeys(typed) {
			safeKey := SanitizeCell(key)
			if safeKey == "" {
				safeKey = "field"
			}
			base := safeKey
			for suffix := 2; ; suffix++ {
				if _, exists := result[safeKey]; !exists {
					break
				}
				safeKey = fmt.Sprintf("%s [%d]", base, suffix)
			}
			result[safeKey] = sanitizeRawValue(typed[key])
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index := range typed {
			result[index] = sanitizeRawValue(typed[index])
		}
		return result
	case string:
		return Sanitize(typed)
	default:
		return typed
	}
}

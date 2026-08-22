// Package jsonpointer evaluates the JSON string representation of RFC 6901
// JSON Pointers against normalized JSON values.
package jsonpointer

import (
	"fmt"
	"strconv"
	"strings"
)

// Resolve evaluates pointer against root and returns the referenced value.
// It accepts the JSON string representation from RFC 6901, not URI fragment
// identifiers. The empty pointer references root.
func Resolve(root any, pointer string) (any, error) {
	if pointer == "" {
		return root, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("invalid JSON Pointer %q: non-empty pointer must start with '/'", pointer)
	}

	current := root
	for index, encoded := range strings.Split(pointer[1:], "/") {
		token, err := decodeToken(encoded)
		if err != nil {
			return nil, fmt.Errorf("invalid JSON Pointer token %d: %w", index, err)
		}

		switch value := current.(type) {
		case map[string]any:
			next, ok := value[token]
			if !ok {
				return nil, fmt.Errorf("JSON Pointer token %d %q references a nonexistent object member", index, token)
			}
			current = next
		case []any:
			arrayIndex, err := parseArrayIndex(token)
			if err != nil {
				return nil, fmt.Errorf("JSON Pointer token %d: %w", index, err)
			}
			if arrayIndex >= len(value) {
				return nil, fmt.Errorf("JSON Pointer token %d index %d is outside array length %d", index, arrayIndex, len(value))
			}
			current = value[arrayIndex]
		default:
			return nil, fmt.Errorf("JSON Pointer token %d %q cannot descend into %T", index, token, current)
		}
	}
	return current, nil
}

// decodeToken applies RFC 6901's required decoding order: ~1 first, then ~0.
func decodeToken(encoded string) (string, error) {
	var b strings.Builder
	b.Grow(len(encoded))
	for i := 0; i < len(encoded); i++ {
		if encoded[i] != '~' {
			b.WriteByte(encoded[i])
			continue
		}
		if i+1 >= len(encoded) {
			return "", fmt.Errorf("trailing '~' escape")
		}
		switch encoded[i+1] {
		case '0':
			b.WriteByte('~')
		case '1':
			b.WriteByte('/')
		default:
			return "", fmt.Errorf("invalid escape ~%c", encoded[i+1])
		}
		i++
	}
	return b.String(), nil
}

func parseArrayIndex(token string) (int, error) {
	if token == "-" {
		return 0, fmt.Errorf("'-' refers to a nonexistent array element and cannot be resolved")
	}
	if token == "" {
		return 0, fmt.Errorf("empty token is not an array index")
	}
	if len(token) > 1 && token[0] == '0' {
		return 0, fmt.Errorf("array index %q has a forbidden leading zero", token)
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return 0, fmt.Errorf("array index %q is not an unsigned base-10 integer", token)
		}
	}
	index, err := strconv.ParseUint(token, 10, 0)
	if err != nil {
		return 0, fmt.Errorf("array index %q is out of range: %w", token, err)
	}
	return int(index), nil
}

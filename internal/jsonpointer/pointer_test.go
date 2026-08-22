package jsonpointer

import (
	"reflect"
	"strings"
	"testing"
)

func TestResolveRFC6901Examples(t *testing.T) {
	doc := map[string]any{
		"foo": []any{"bar", "baz"},
		"":    float64(0),
		"a/b": float64(1),
		"c%d": float64(2),
		"e^f": float64(3),
		"g|h": float64(4),
		"i\\j": float64(5),
		"k\"l": float64(6),
		" ":    float64(7),
		"m~n": float64(8),
	}

	tests := []struct {
		pointer string
		want    any
	}{
		{"", doc},
		{"/foo", []any{"bar", "baz"}},
		{"/foo/0", "bar"},
		{"/", float64(0)},
		{"/a~1b", float64(1)},
		{"/c%d", float64(2)},
		{"/e^f", float64(3)},
		{"/g|h", float64(4)},
		{"/i\\j", float64(5)},
		{"/k\"l", float64(6)},
		{"/ ", float64(7)},
		{"/m~0n", float64(8)},
	}

	for _, tt := range tests {
		t.Run(tt.pointer, func(t *testing.T) {
			got, err := Resolve(doc, tt.pointer)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tt.pointer, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Resolve(%q) = %#v; want %#v", tt.pointer, got, tt.want)
			}
		})
	}
}

func TestResolveDecodesEscapesOnceInRequiredOrder(t *testing.T) {
	doc := map[string]any{"~1": "literal tilde one", "/": "slash"}
	got, err := Resolve(doc, "/~01")
	if err != nil {
		t.Fatal(err)
	}
	if got != "literal tilde one" {
		t.Fatalf("got %#v; escape order incorrectly produced slash", got)
	}
}

func TestResolveRejectsInvalidPointers(t *testing.T) {
	doc := map[string]any{
		"array": []any{"zero"},
		"value": "scalar",
	}

	tests := []struct {
		name    string
		pointer string
		wantErr string
	}{
		{"missing slash", "array/0", "must start"},
		{"invalid escape", "/~2", "invalid escape"},
		{"trailing escape", "/foo~", "trailing"},
		{"missing member", "/missing", "nonexistent object member"},
		{"array dash", "/array/-", "nonexistent array element"},
		{"array leading zero", "/array/00", "leading zero"},
		{"array nonnumeric", "/array/nope", "not an unsigned"},
		{"array bounds", "/array/1", "outside array length"},
		{"scalar descend", "/value/child", "cannot descend"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Resolve(doc, tt.pointer)
			if err == nil {
				t.Fatalf("Resolve(%q) unexpectedly succeeded", tt.pointer)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Resolve(%q) error %q does not contain %q", tt.pointer, err, tt.wantErr)
			}
		})
	}
}

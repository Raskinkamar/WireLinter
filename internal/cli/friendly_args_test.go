package cli

import (
	"reflect"
	"testing"
)

func TestNormalizeFriendlyArgs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "mercado pago", in: []string{"mercado", "pago", "http://localhost:8000/webhook"}, want: []string{"mercadopago", "http://localhost:8000/webhook"}},
		{name: "whatsapp verification", in: []string{"whatsapp", "verification", "capture.json"}, want: []string{"whatsapp-verification", "capture.json"}},
		{name: "whatsapp api", in: []string{"whatsapp", "api", "https://graph.facebook.com"}, want: []string{"whatsapp-api", "https://graph.facebook.com"}},
		{name: "github api", in: []string{"github", "api", "https://api.github.com"}, want: []string{"github-api", "https://api.github.com"}},
		{name: "normal command untouched", in: []string{"listen", "stripe", "http://localhost:3000/webhook"}, want: []string{"listen", "stripe", "http://localhost:3000/webhook"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeFriendlyArgs(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("normalizeFriendlyArgs(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

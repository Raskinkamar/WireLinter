package cli

import (
	"io"
	"strings"
)

// RunFriendly normalizes a few natural multi-word provider names before the
// guided entrypoint sees them. This lets shell users type commands such as
// `wirelint whatsapp verification ...` without quoting or learning pack IDs.
func RunFriendly(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return RunInteractive(normalizeFriendlyArgs(args), stdin, stdout, stderr)
}

func normalizeFriendlyArgs(args []string) []string {
	if len(args) < 2 {
		return args
	}

	first := strings.ToLower(strings.TrimSpace(args[0]))
	second := strings.ToLower(strings.TrimSpace(args[1]))

	alias := ""
	switch first + " " + second {
	case "mercado pago":
		alias = "mercadopago"
	case "whatsapp verification", "whatsapp verify":
		alias = "whatsapp-verification"
	case "whatsapp api":
		alias = "whatsapp-api"
	case "github api", "github graphql":
		alias = "github-api"
	case "meta whatsapp":
		alias = "whatsapp"
	}
	if alias == "" {
		return args
	}

	normalized := make([]string, 0, len(args)-1)
	normalized = append(normalized, alias)
	normalized = append(normalized, args[2:]...)
	return normalized
}

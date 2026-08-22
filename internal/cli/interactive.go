package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Raskinkamar/WireLinter/internal/pack"
	builtinpacks "github.com/Raskinkamar/WireLinter/packs"
)

// RunInteractive is the user-facing CLI entrypoint. It keeps the explicit
// commands available for scripts and CI, while making the default path useful
// to somebody who has never read WireLinter's internal terminology.
func RunInteractive(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if stdin == nil {
		stdin = strings.NewReader("")
	}

	if len(args) == 0 {
		return runQuickStart(stdin, stdout, stderr)
	}

	switch args[0] {
	case "integrations":
		return runFriendlyIntegrations(args[1:], stdout, stderr)
	case "try":
		return runDemo(args[1:], stdout, stderr)
	case "demo", "lint", "listen", "proxy", "validate-pack", "providers", "version", "--version", "-v", "help", "--help", "-h":
		return Run(args, stdout, stderr)
	}

	matches, err := resolveIntegration(args[0])
	if err != nil {
		return executionError(stderr, "resolve integration", err)
	}
	if len(matches) == 0 {
		return Run(args, stdout, stderr)
	}

	wizard := newQuickWizard(stdin, stdout, stderr)
	choice, ok := wizard.chooseIntegration(args[0], matches)
	if !ok {
		return 2
	}
	return runIntegrationShortcut(choice, args[1:], wizard, stdout, stderr)
}

type integrationKind int

const (
	integrationUnknown integrationKind = iota
	integrationInbound
	integrationOutbound
)

type integrationChoice struct {
	ID      string
	Name    string
	Vendor  string
	Surface string
	Region  string
	Kind    integrationKind
}

var humanIntegrationAliases = map[string]string{
	"mercadopago":         "mercadopago-webhooks",
	"whatsapp":            "meta-whatsapp-webhooks",
	"whatsappwebhook":     "meta-whatsapp-webhooks",
	"whatsappwebhooks":    "meta-whatsapp-webhooks",
	"whatsappverification": "meta-whatsapp-webhook-verification",
	"whatsappverify":      "meta-whatsapp-webhook-verification",
	"whatsappapi":         "meta-whatsapp-cloud-api",
	"whatsappcloudapi":    "meta-whatsapp-cloud-api",
	"githubapi":           "github-graphql-api",
	"githubgraphql":       "github-graphql-api",
	"githubgraphqlapi":    "github-graphql-api",
}

func runIntegrationShortcut(choice integrationChoice, args []string, wizard *quickWizard, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return wizard.runForIntegration(choice)
	}

	first := strings.TrimSpace(args[0])
	if looksLikeHTTPURL(first) {
		switch choice.Kind {
		case integrationInbound:
			return runListen(append([]string{choice.ID, first}, args[1:]...), stdout, stderr)
		case integrationOutbound:
			return runProxy(append([]string{choice.ID, first}, args[1:]...), stdout, stderr)
		default:
			fmt.Fprintf(stderr, "wirelint: %s can not be safely classified as inbound or outbound\n", choice.Name)
			fmt.Fprintln(stderr, "use `wirelint listen ...` or `wirelint proxy ...` explicitly for this integration")
			return 2
		}
	}

	return runLint(append([]string{choice.ID}, args...), stdout, stderr)
}

func runQuickStart(stdin io.Reader, stdout, stderr io.Writer) int {
	wizard := newQuickWizard(stdin, stdout, stderr)
	fmt.Fprintln(stdout, "WIRELINT")
	fmt.Fprintln(stdout, "Inspect an integration without learning WireLinter internals first.")
	fmt.Fprintln(stdout)

	query, ok := wizard.prompt("Integration (try mercadopago, whatsapp, stripe): ")
	if !ok || strings.TrimSpace(query) == "" {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Quick examples:")
		fmt.Fprintln(stdout, "  wirelint mercadopago http://localhost:8000/webhook")
		fmt.Fprintln(stdout, "  wirelint whatsapp http://localhost:8000/webhook")
		fmt.Fprintln(stdout, "  wirelint github-api https://api.github.com")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Run `wirelint integrations` to browse everything bundled in this build.")
		return 0
	}

	matches, err := resolveIntegration(query)
	if err != nil {
		return executionError(stderr, "resolve integration", err)
	}
	if len(matches) == 0 {
		fmt.Fprintf(stderr, "wirelint: no bundled integration matches %q\n", query)
		fmt.Fprintln(stderr, "run `wirelint integrations` to browse available integrations")
		return 2
	}

	choice, ok := wizard.chooseIntegration(query, matches)
	if !ok {
		return 2
	}
	return wizard.runForIntegration(choice)
}

type quickWizard struct {
	reader *bufio.Reader
	out    io.Writer
	err    io.Writer
}

func newQuickWizard(in io.Reader, out, errOut io.Writer) *quickWizard {
	return &quickWizard{reader: bufio.NewReader(in), out: out, err: errOut}
}

func (w *quickWizard) prompt(label string) (string, bool) {
	fmt.Fprint(w.out, label)
	line, err := w.reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if err != nil && line == "" {
		return "", false
	}
	return line, true
}

func (w *quickWizard) chooseIntegration(query string, matches []integrationChoice) (integrationChoice, bool) {
	if len(matches) == 1 {
		return matches[0], true
	}

	fmt.Fprintf(w.out, "\n%s matches more than one integration:\n", query)
	for i, choice := range matches {
		fmt.Fprintf(w.out, "  %d) %s", i+1, choice.Name)
		if choice.ID != "" {
			fmt.Fprintf(w.out, "  [%s]", choice.ID)
		}
		fmt.Fprintln(w.out)
	}

	answer, ok := w.prompt("Choose a number: ")
	if !ok {
		fmt.Fprintln(w.err, "wirelint: selection cancelled")
		return integrationChoice{}, false
	}
	selected, err := strconv.Atoi(answer)
	if err != nil || selected < 1 || selected > len(matches) {
		fmt.Fprintln(w.err, "wirelint: invalid integration selection")
		return integrationChoice{}, false
	}
	return matches[selected-1], true
}

func (w *quickWizard) runForIntegration(choice integrationChoice) int {
	fmt.Fprintf(w.out, "\n%s\n", choice.Name)

	switch choice.Kind {
	case integrationInbound:
		fmt.Fprintln(w.out, "  1) Inspect a live webhook")
		fmt.Fprintln(w.out, "  2) Analyze a saved capture")
		answer, ok := w.prompt("Choose [1]: ")
		if !ok || answer == "" || answer == "1" {
			return w.startInbound(choice)
		}
		if answer == "2" {
			return w.analyzeSaved(choice)
		}
	case integrationOutbound:
		fmt.Fprintln(w.out, "  1) Inspect live API calls")
		fmt.Fprintln(w.out, "  2) Analyze a saved capture")
		answer, ok := w.prompt("Choose [1]: ")
		if !ok || answer == "" || answer == "1" {
			return w.startOutbound(choice)
		}
		if answer == "2" {
			return w.analyzeSaved(choice)
		}
	default:
		fmt.Fprintln(w.out, "  1) Inspect a live webhook")
		fmt.Fprintln(w.out, "  2) Inspect live API calls")
		fmt.Fprintln(w.out, "  3) Analyze a saved capture")
		answer, ok := w.prompt("Choose: ")
		if !ok {
			fmt.Fprintln(w.err, "wirelint: selection cancelled")
			return 2
		}
		switch answer {
		case "1":
			return w.startInbound(choice)
		case "2":
			return w.startOutbound(choice)
		case "3":
			return w.analyzeSaved(choice)
		}
	}

	fmt.Fprintln(w.err, "wirelint: invalid action selection")
	return 2
}

func (w *quickWizard) startInbound(choice integrationChoice) int {
	target, ok := w.prompt("Your local webhook URL: ")
	if !ok || strings.TrimSpace(target) == "" {
		fmt.Fprintln(w.err, "wirelint: local webhook URL is required")
		return 2
	}
	if !looksLikeHTTPURL(target) {
		fmt.Fprintf(w.err, "wirelint: %q is not a valid http(s) URL\n", target)
		return 2
	}
	fmt.Fprintln(w.out)
	return runListen([]string{choice.ID, target}, w.out, w.err)
}

func (w *quickWizard) startOutbound(choice integrationChoice) int {
	target, ok := w.prompt("Provider base URL: ")
	if !ok || strings.TrimSpace(target) == "" {
		fmt.Fprintln(w.err, "wirelint: provider base URL is required")
		return 2
	}
	if !looksLikeHTTPURL(target) {
		fmt.Fprintf(w.err, "wirelint: %q is not a valid http(s) URL\n", target)
		return 2
	}
	fmt.Fprintln(w.out)
	return runProxy([]string{choice.ID, target}, w.out, w.err)
}

func (w *quickWizard) analyzeSaved(choice integrationChoice) int {
	path, ok := w.prompt("Capture file: ")
	if !ok || strings.TrimSpace(path) == "" {
		fmt.Fprintln(w.err, "wirelint: capture file is required")
		return 2
	}
	return runLint([]string{choice.ID, path}, w.out, w.err)
}

func resolveIntegration(input string) ([]integrationChoice, error) {
	query := normalizeIntegrationTerm(input)
	if query == "" {
		return nil, nil
	}

	providers := builtinpacks.Providers()
	for _, id := range providers {
		if strings.EqualFold(id, strings.TrimSpace(input)) {
			choice, err := loadIntegrationChoice(id)
			if err != nil {
				return nil, err
			}
			return []integrationChoice{choice}, nil
		}
	}

	if target, ok := humanIntegrationAliases[query]; ok && isBundledProvider(target) {
		choice, err := loadIntegrationChoice(target)
		if err != nil {
			return nil, err
		}
		return []integrationChoice{choice}, nil
	}

	catalog, err := integrationCatalog()
	if err != nil {
		return nil, err
	}

	var vendorMatches []integrationChoice
	var partialMatches []integrationChoice
	for _, choice := range catalog {
		if query == normalizeIntegrationTerm(choice.ID) || query == normalizeIntegrationTerm(choice.Name) {
			return []integrationChoice{choice}, nil
		}
		if choice.Vendor != "" && query == normalizeIntegrationTerm(choice.Vendor) {
			vendorMatches = append(vendorMatches, choice)
			continue
		}
		haystacks := []string{choice.ID, choice.Name, choice.Vendor, choice.Surface}
		for _, value := range haystacks {
			normalized := normalizeIntegrationTerm(value)
			if normalized != "" && strings.Contains(normalized, query) {
				partialMatches = append(partialMatches, choice)
				break
			}
		}
	}

	if len(vendorMatches) > 0 {
		return vendorMatches, nil
	}
	return partialMatches, nil
}

func integrationCatalog() ([]integrationChoice, error) {
	providers := builtinpacks.Providers()
	choices := make([]integrationChoice, 0, len(providers))
	for _, id := range providers {
		choice, err := loadIntegrationChoice(id)
		if err != nil {
			return nil, err
		}
		choices = append(choices, choice)
	}
	sort.Slice(choices, func(i, j int) bool {
		if choices[i].Name == choices[j].Name {
			return choices[i].ID < choices[j].ID
		}
		return choices[i].Name < choices[j].Name
	})
	return choices, nil
}

func loadIntegrationChoice(id string) (integrationChoice, error) {
	fsys, err := builtinpacks.Provider(id)
	if err != nil {
		return integrationChoice{}, err
	}
	loader, err := pack.NewLoader()
	if err != nil {
		return integrationChoice{}, err
	}
	loaded, err := loader.LoadFS(fsys)
	if err != nil {
		return integrationChoice{}, err
	}
	choice := integrationChoice{
		ID:      loaded.Manifest.ID,
		Name:    loaded.Manifest.Name,
		Vendor:  metadataString(loaded.Manifest.Metadata, "vendor"),
		Surface: metadataString(loaded.Manifest.Metadata, "surface"),
		Region:  metadataString(loaded.Manifest.Metadata, "region"),
	}
	choice.Kind = inferIntegrationKind(choice)
	return choice, nil
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func inferIntegrationKind(choice integrationChoice) integrationKind {
	text := strings.ToLower(strings.Join([]string{choice.ID, choice.Name, choice.Surface}, " "))
	for _, marker := range []string{"webhook", "hook", "callback", "verification", "connect"} {
		if strings.Contains(text, marker) {
			return integrationInbound
		}
	}
	for _, marker := range []string{"graphql", " api", "-api", "cloud-api"} {
		if strings.Contains(text, marker) {
			return integrationOutbound
		}
	}
	return integrationUnknown
}

func normalizeIntegrationTerm(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, value)
}

func looksLikeHTTPURL(value string) bool {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return parsed.Host != ""
}

func runFriendlyIntegrations(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("integrations", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var region string
	flags.StringVar(&region, "region", "", "filter integrations by region, for example BR")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "wirelint integrations: no positional arguments are accepted")
		return 2
	}

	catalog, err := integrationCatalog()
	if err != nil {
		return executionError(stderr, "load integrations", err)
	}
	region = strings.TrimSpace(region)

	fmt.Fprintln(stdout, "WIRELINT / integrations")
	for _, choice := range catalog {
		if region != "" && choice.Region != region {
			continue
		}
		fmt.Fprintf(stdout, "%-38s %s\n", choice.Name, choice.ID)
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Start with: wirelint <integration> <local-url-or-capture>")
	return 0
}

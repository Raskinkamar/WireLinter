package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Raskinkamar/WireLinter/internal/engine"
	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
	builtinpacks "github.com/Raskinkamar/WireLinter/packs"
)

var Version = "dev"

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}

	switch args[0] {
	case "demo":
		return runDemo(args[1:], stdout, stderr)
	case "lint":
		return runLint(args[1:], stdout, stderr)
	case "listen":
		return runListen(args[1:], stdout, stderr)
	case "proxy":
		return runProxy(args[1:], stdout, stderr)
	case "validate-pack":
		return runValidatePack(args[1:], stdout, stderr)
	case "providers":
		return runProviders(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, Version)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		if isBundledProvider(args[0]) {
			return runLint(args, stdout, stderr)
		}
		fmt.Fprintf(stderr, "wirelint: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

const demoTraceJSON = `{
  "schemaVersion": 1,
  "traceId": "demo_github_graphql_errors",
  "provider": "github-graphql-api",
  "startedAt": "2026-08-18T05:00:00Z",
  "envelopes": [{
    "id": "demo_exchange",
    "provider": "github-graphql-api",
    "direction": "outbound",
    "receivedAt": "2026-08-18T05:00:00Z",
    "request": {
      "method": "POST",
      "url": "https://api.github.com/graphql",
      "headers": [
        {"name": "Authorization", "value": "Bearer <redacted>", "redacted": true},
        {"name": "Content-Type", "value": "application/json"}
      ],
      "headersCompleteness": "complete",
      "rawQuery": "",
      "queryFidelity": "exact",
      "query": [],
      "bodyFidelity": "exact",
      "rawBodyBase64": "eyJxdWVyeSI6InF1ZXJ5IFZpZXdlciB7IHZpZXdlciB7IGxvZ2luIH0gfSJ9",
      "decodedBody": {"query": "query Viewer { viewer { login } }"}
    },
    "response": {
      "status": 200,
      "headers": [
        {"name": "Content-Type", "value": "application/json"},
        {"name": "X-RateLimit-Remaining", "value": "4999"}
      ],
      "headersCompleteness": "complete",
      "bodyFidelity": "exact",
      "rawBodyBase64": "eyJkYXRhIjpudWxsLCJlcnJvcnMiOlt7Im1lc3NhZ2UiOiJTb21ldGhpbmcgd2VudCB3cm9uZyJ9XX0=",
      "decodedBody": {"data": null, "errors": [{"message": "Something went wrong"}]},
      "durationMs": 42.3
    }
  }],
  "observations": []
}`

func runDemo(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "wirelint demo: no arguments are accepted")
		return 2
	}

	loader, err := pack.NewLoader()
	if err != nil {
		return executionError(stderr, "initialize demo", err)
	}
	loaded, err := loadSelectedPack(loader, "github-graphql-api", "")
	if err != nil {
		return executionError(stderr, "load demo contract", err)
	}
	var trace model.Trace
	decoder := json.NewDecoder(strings.NewReader(demoTraceJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&trace); err != nil {
		return executionError(stderr, "load demo trace", err)
	}
	evaluator, err := engine.New()
	if err != nil {
		return executionError(stderr, "initialize demo engine", err)
	}
	report, err := evaluator.Evaluate(trace, loaded)
	if err != nil {
		return executionError(stderr, "evaluate demo trace", err)
	}

	fmt.Fprintln(stdout, "WireLinter demo · GitHub GraphQL API")
	fmt.Fprintln(stdout, "A provider returned HTTP 200 with a GraphQL error in the response body.")
	fmt.Fprintln(stdout)
	writeStyledTextReport(stdout, report)
	fmt.Fprintln(stdout, "This failure is intentional. WireLinter separated transport success from the integration result.")
	return 0
}

func runLint(args []string, stdout, stderr io.Writer) int {
	providerShortcut := ""
	if len(args) > 0 && isBundledProvider(args[0]) {
		providerShortcut = args[0]
		args = args[1:]
	}

	normalizedArgs := make([]string, 0, len(args)+2)
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") && !strings.Contains(arg, "=") {
			candidate := strings.TrimPrefix(arg, "--")
			if isBundledProvider(candidate) {
				normalizedArgs = append(normalizedArgs, "--provider", candidate)
				continue
			}
		}
		normalizedArgs = append(normalizedArgs, arg)
	}

	flags := flag.NewFlagSet("lint", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var packDir string
	provider := providerShortcut
	var tracePath string
	var format string
	flags.StringVar(&provider, "provider", providerShortcut, "bundled official provider pack (for example: stripe)")
	flags.StringVar(&packDir, "pack", "", "external provider pack directory")
	flags.StringVar(&tracePath, "trace", "", "canonical Trace JSON file")
	flags.StringVar(&format, "format", "text", "output format: text or json")
	if err := flags.Parse(normalizedArgs); err != nil {
		return 2
	}
	if tracePath == "" && flags.NArg() == 1 {
		tracePath = flags.Arg(0)
	} else if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "wirelint lint: expected one trace file")
		fmt.Fprintln(stderr, "try: wirelint <provider> <trace.json>")
		return 2
	}
	if tracePath == "" {
		if provider != "" {
			fmt.Fprintf(stderr, "wirelint lint: trace missing for %s\n", provider)
			fmt.Fprintf(stderr, "try: wirelint %s <trace.json>\n", provider)
		} else {
			fmt.Fprintln(stderr, "wirelint lint: a trace path is required")
			fmt.Fprintln(stderr, "try: wirelint <provider> <trace.json>")
		}
		return 2
	}
	if err := validatePackSelection(provider, packDir); err != nil {
		fmt.Fprintf(stderr, "wirelint lint: %v\n", err)
		return 2
	}
	if format != "text" && format != "json" {
		fmt.Fprintf(stderr, "wirelint lint: unsupported format %q (expected text or json)\n", format)
		return 2
	}

	loader, err := pack.NewLoader()
	if err != nil {
		return executionError(stderr, "initialize pack loader", err)
	}
	loaded, err := loadSelectedPack(loader, provider, packDir)
	if err != nil {
		return executionError(stderr, "load provider pack", err)
	}
	trace, err := readTrace(tracePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(stderr, "wirelint: trace file not found: %s\n\n", tracePath)
			if provider != "" {
				fmt.Fprintln(stderr, "A trace is a real HTTP capture, not a placeholder filename.")
				fmt.Fprintln(stderr, "For an inbound webhook, capture one first with:")
				fmt.Fprintf(stderr, "  wirelint listen %s <local-webhook-url> --save-dir .wirelint/traces\n\n", provider)
				fmt.Fprintln(stderr, "Then lint the saved file with:")
				fmt.Fprintf(stderr, "  wirelint %s .wirelint/traces/<trace-id>.json\n", provider)
			}
			return 2
		}
		return executionError(stderr, "read trace", err)
	}

	evaluator, err := engine.NewWithSecrets(envSecretResolver{specs: loaded.Manifest.Secrets})
	if err != nil {
		return executionError(stderr, "initialize engine", err)
	}
	report, err := evaluator.Evaluate(trace, loaded)
	if err != nil {
		return executionError(stderr, "evaluate trace", err)
	}

	if format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return executionError(stderr, "write JSON report", err)
		}
	} else {
		writeStyledTextReport(stdout, report)
	}

	if report.Summary.Errors > 0 {
		return 1
	}
	return 0
}

func runValidatePack(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate-pack", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var packDir string
	var provider string
	flags.StringVar(&provider, "provider", "", "bundled official provider pack")
	flags.StringVar(&packDir, "pack", "", "external provider pack directory")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if packDir == "" && provider == "" && flags.NArg() == 1 {
		packDir = flags.Arg(0)
	} else if flags.NArg() > 0 {
		fmt.Fprintln(stderr, "wirelint validate-pack: pass one external pack directory or use --provider")
		return 2
	}
	if err := validatePackSelection(provider, packDir); err != nil {
		fmt.Fprintf(stderr, "wirelint validate-pack: %v\n", err)
		return 2
	}

	loader, err := pack.NewLoader()
	if err != nil {
		return executionError(stderr, "initialize pack loader", err)
	}
	loaded, err := loadSelectedPack(loader, provider, packDir)
	if err != nil {
		return executionError(stderr, "validate provider pack", err)
	}
	fmt.Fprintf(stdout, "VALID %s · pack %s · protocol %s · %d rules · %d signatures · %d secret matches · %d digest matches · %d schemas\n",
		loaded.Manifest.Name,
		loaded.Manifest.PackVersion,
		loaded.Manifest.PackProtocol,
		len(loaded.Rules),
		len(loaded.Signatures),
		len(loaded.SecretMatches),
		len(loaded.DigestMatches),
		len(loaded.Schemas),
	)
	return 0
}

func runProviders(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("providers", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var region string
	flags.StringVar(&region, "region", "", "filter bundled providers by metadata.region (for example: BR)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "wirelint providers: no positional arguments are accepted")
		return 2
	}

	providers := builtinpacks.Providers()
	if len(providers) == 0 {
		fmt.Fprintln(stdout, "No official provider packs are bundled in this build.")
		return 0
	}
	region = strings.TrimSpace(region)
	if region == "" {
		for _, provider := range providers {
			fmt.Fprintln(stdout, provider)
		}
		return 0
	}

	loader, err := pack.NewLoader()
	if err != nil {
		return executionError(stderr, "initialize pack loader", err)
	}
	for _, provider := range providers {
		fsys, err := builtinpacks.Provider(provider)
		if err != nil {
			return executionError(stderr, "open bundled provider", err)
		}
		loaded, err := loader.LoadFS(fsys)
		if err != nil {
			return executionError(stderr, "load bundled provider metadata", err)
		}
		if metadataRegion(loaded.Manifest.Metadata) == region {
			fmt.Fprintln(stdout, provider)
		}
	}
	return 0
}

func metadataRegion(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata["region"]
	if !ok {
		return ""
	}
	region, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(region)
}

func isBundledProvider(name string) bool {
	for _, provider := range builtinpacks.Providers() {
		if provider == name {
			return true
		}
	}
	return false
}

func validatePackSelection(provider, packDir string) error {
	provider = strings.TrimSpace(provider)
	packDir = strings.TrimSpace(packDir)
	switch {
	case provider != "" && packDir != "":
		return fmt.Errorf("--provider and --pack are mutually exclusive")
	case provider == "" && packDir == "":
		return fmt.Errorf("select a bundled pack with --provider or an external pack with --pack")
	default:
		return nil
	}
}

func loadSelectedPack(loader *pack.Loader, provider, packDir string) (*pack.Loaded, error) {
	if strings.TrimSpace(provider) != "" {
		fsys, err := builtinpacks.Provider(strings.TrimSpace(provider))
		if err != nil {
			return nil, err
		}
		return loader.LoadFS(fsys)
	}
	return loader.LoadDir(strings.TrimSpace(packDir))
}

func readTrace(path string) (model.Trace, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return model.Trace{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var trace model.Trace
	if err := decoder.Decode(&trace); err != nil {
		return model.Trace{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return model.Trace{}, fmt.Errorf("multiple JSON documents are not allowed")
		}
		return model.Trace{}, fmt.Errorf("read trailing JSON: %w", err)
	}
	return trace, nil
}

type envSecretResolver struct {
	specs map[string]pack.SecretSpec
}

func (r envSecretResolver) Lookup(ref string) (string, bool, error) {
	spec, ok := r.specs[ref]
	if !ok {
		return "", false, fmt.Errorf("unknown secret ref %q", ref)
	}
	value, present := os.LookupEnv(spec.Env)
	return value, present, nil
}

func writeTextReport(w io.Writer, report model.Report) {
	fmt.Fprintf(w, "WireLinter · %s\n", report.Provider)
	if report.Pack != nil {
		fmt.Fprintf(w, "Pack %s %s · protocol %s\n", report.Pack.ID, report.Pack.Version, report.Pack.Protocol)
	}
	fmt.Fprintf(w, "Trace %s\n\n", report.TraceID)

	for _, result := range report.Results {
		status := strings.ToUpper(result.Kind)
		label := status
		if result.Kind == "fail" {
			label += "/" + strings.ToUpper(result.Level)
		}
		if result.MessageID != "" {
			fmt.Fprintf(w, "%s %s [%s]\n", label, result.RuleID, result.MessageID)
		} else {
			fmt.Fprintf(w, "%s %s\n", label, result.RuleID)
		}
		fmt.Fprintf(w, "  %s\n", result.Message)
		if result.DocsRef != nil && result.DocsRef.URL != "" && result.Kind != "pass" {
			fmt.Fprintf(w, "  docs: %s\n", result.DocsRef.URL)
		}
	}

	fmt.Fprintf(w, "\n%d pass · %d fail · %d open · %d not-applicable · %d errors · %d warnings · %d notes\n",
		report.Summary.Pass,
		report.Summary.Fail,
		report.Summary.Open,
		report.Summary.NotApplicable,
		report.Summary.Errors,
		report.Summary.Warnings,
		report.Summary.Notes,
	)
}

func executionError(stderr io.Writer, operation string, err error) int {
	fmt.Fprintf(stderr, "wirelint: %s: %v\n", operation, err)
	return 2
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "WireLinter - integration contract linter")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  wirelint demo")
	fmt.Fprintln(w, "  wirelint <provider> <trace.json>")
	fmt.Fprintln(w, "  wirelint lint <provider> <trace.json>")
	fmt.Fprintln(w, "  wirelint lint --provider <id> <trace.json>")
	fmt.Fprintln(w, "  wirelint lint --pack <dir> <trace.json>")
	fmt.Fprintln(w, "  wirelint listen --provider <id> --forward-to <url>")
	fmt.Fprintln(w, "  wirelint proxy --provider <id> --target <base-url>")
	fmt.Fprintln(w, "  wirelint validate-pack --provider <id>")
	fmt.Fprintln(w, "  wirelint validate-pack --pack <dir>")
	fmt.Fprintln(w, "  wirelint providers [--region <code>]")
	fmt.Fprintln(w, "  wirelint version")
}

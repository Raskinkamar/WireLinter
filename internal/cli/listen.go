package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/Raskinkamar/WireLinter/internal/engine"
	"github.com/Raskinkamar/WireLinter/internal/listener"
	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
)

var safeTraceID = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func runListen(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runListenContext(ctx, args, stdout, stderr)
}

func runListenContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runListenContextWithReady(ctx, args, stdout, stderr, nil)
}

// runListenContextWithReady keeps the production command API small while
// giving same-package integration tests an explicit readiness boundary. The
// hook is not part of the user/plugin surface.
func runListenContextWithReady(ctx context.Context, args []string, stdout, stderr io.Writer, readyHook func(net.Addr)) int {
	args = normalizeListenArgs(args)
	flags := flag.NewFlagSet("listen", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var provider string
	var packDir string
	var forwardTo string
	var address string
	var saveDir string
	var allowRemoteForward bool
	var allowPublicListen bool
	var maxBodyBytes int64
	var maxResponseCaptureBytes int64

	flags.StringVar(&provider, "provider", "", "bundled official provider pack")
	flags.StringVar(&packDir, "pack", "", "external provider pack directory")
	flags.StringVar(&forwardTo, "forward-to", "", "local application webhook URL")
	flags.StringVar(&address, "addr", listener.DefaultListenAddress, "listener address")
	flags.StringVar(&saveDir, "save-dir", "", "optional directory for canonical Trace JSON files")
	flags.BoolVar(&allowRemoteForward, "allow-remote-forward", false, "allow forwarding webhook payloads to a non-loopback host")
	flags.BoolVar(&allowPublicListen, "allow-public-listen", false, "allow binding the listener to a non-loopback interface")
	flags.Int64Var(&maxBodyBytes, "max-body-bytes", listener.DefaultMaxRequestBodyBytes, "maximum inbound webhook body size")
	flags.Int64Var(&maxResponseCaptureBytes, "max-response-capture-bytes", listener.DefaultMaxResponseCaptureBytes, "maximum application response bytes retained in Trace evidence")

	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "wirelint listen: positional arguments are not supported")
		return 2
	}
	if err := validatePackSelection(provider, packDir); err != nil {
		fmt.Fprintf(stderr, "wirelint listen: %v\n", err)
		return 2
	}
	if strings.TrimSpace(forwardTo) == "" {
		fmt.Fprintln(stderr, "wirelint listen: local webhook URL is required (--forward-to is required in explicit form)")
		fmt.Fprintln(stderr, "try: wirelint listen <provider> <local-webhook-url>")
		return 2
	}
	if maxBodyBytes <= 0 {
		fmt.Fprintln(stderr, "wirelint listen: --max-body-bytes must be greater than zero")
		return 2
	}
	if maxResponseCaptureBytes <= 0 {
		fmt.Fprintln(stderr, "wirelint listen: --max-response-capture-bytes must be greater than zero")
		return 2
	}
	if err := listener.ValidateListenAddress(address, allowPublicListen); err != nil {
		fmt.Fprintf(stderr, "wirelint listen: %v\n", err)
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

	evaluator, err := engine.NewWithSecrets(envSecretResolver{specs: loaded.Manifest.Secrets})
	if err != nil {
		return executionError(stderr, "initialize engine", err)
	}

	reporter, err := newLiveReporter(liveReporterConfig{
		Evaluator: evaluator,
		Pack:      loaded,
		Stdout:    stdout,
		Stderr:    stderr,
		SaveDir:   saveDir,
	})
	if err != nil {
		return executionError(stderr, "initialize live reporter", err)
	}

	localListener, err := listener.New(listener.Config{
		Provider:                loaded.Manifest.ID,
		ForwardTo:               forwardTo,
		AllowRemoteForward:      allowRemoteForward,
		MaxRequestBodyBytes:     maxBodyBytes,
		MaxResponseCaptureBytes: maxResponseCaptureBytes,
		OnDelivery:              reporter.Enqueue,
	})
	if err != nil {
		return executionError(stderr, "initialize listener", err)
	}

	warnMissingSecrets(stderr, loaded.Manifest.Secrets)

	serveErr := localListener.Serve(ctx, address, allowPublicListen, func(actual net.Addr) {
		fmt.Fprintf(stdout, "WireLinter listening on http://%s/\n", displayListenerAddress(actual))
		fmt.Fprintf(stdout, "Provider: %s\n", loaded.Manifest.ID)
		fmt.Fprintf(stdout, "Forwarding to: %s\n", localListener.Target())
		if strings.TrimSpace(saveDir) == "" {
			fmt.Fprintln(stdout, "Trace persistence: off")
		} else {
			fmt.Fprintf(stdout, "Trace persistence: %s\n", reporter.saveDir)
		}
		fmt.Fprintln(stdout, "Press Ctrl+C to stop.")
		fmt.Fprintln(stdout)
		if readyHook != nil {
			readyHook(actual)
		}
	})

	// Serve waits for active HTTP handlers during graceful shutdown. At that
	// point no new Enqueue calls can begin, so waiting for asynchronously queued
	// diagnostics cannot race with WaitGroup.Add.
	reporter.Wait()
	if serveErr != nil {
		return executionError(stderr, "listener stopped unexpectedly", serveErr)
	}
	return 0
}

func normalizeListenArgs(args []string) []string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args
	}
	normalized := []string{"--provider", args[0]}
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		normalized = append(normalized, "--forward-to", rest[0])
		rest = rest[1:]
	}
	return append(normalized, rest...)
}

func displayListenerAddress(address net.Addr) string {
	if address == nil {
		return listener.DefaultListenAddress
	}
	return address.String()
}

func warnMissingSecrets(stderr io.Writer, specs map[string]pack.SecretSpec) {
	if len(specs) == 0 {
		return
	}
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		if _, present := os.LookupEnv(spec.Env); !present {
			names = append(names, spec.Env)
		}
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	fmt.Fprintf(stderr, "wirelint: warning: %s not set; rules that require these secrets will report OPEN rather than guessing\n", strings.Join(names, ", "))
}

type liveReporterConfig struct {
	Evaluator *engine.Evaluator
	Pack      *pack.Loaded
	Stdout    io.Writer
	Stderr    io.Writer
	SaveDir   string
}

type liveReporter struct {
	evaluator *engine.Evaluator
	pack      *pack.Loaded
	stdout    io.Writer
	stderr    io.Writer
	saveDir   string

	mu sync.Mutex
	wg sync.WaitGroup
}

func newLiveReporter(config liveReporterConfig) (*liveReporter, error) {
	if config.Evaluator == nil {
		return nil, fmt.Errorf("evaluator is nil")
	}
	if config.Pack == nil {
		return nil, fmt.Errorf("provider pack is nil")
	}
	if config.Stdout == nil || config.Stderr == nil {
		return nil, fmt.Errorf("output writer is nil")
	}

	saveDir := strings.TrimSpace(config.SaveDir)
	if saveDir != "" {
		absolute, err := filepath.Abs(saveDir)
		if err != nil {
			return nil, fmt.Errorf("resolve save directory: %w", err)
		}
		if err := os.MkdirAll(absolute, 0o700); err != nil {
			return nil, fmt.Errorf("create save directory: %w", err)
		}
		saveDir = absolute
	}

	return &liveReporter{
		evaluator: config.Evaluator,
		pack:      config.Pack,
		stdout:    config.Stdout,
		stderr:    config.Stderr,
		saveDir:   saveDir,
	}, nil
}

// Enqueue intentionally returns immediately after scheduling work. The HTTP
// handler has already relayed the application response, and live rule
// evaluation/persistence must not become part of provider acknowledgement
// latency.
func (r *liveReporter) Enqueue(delivery listener.Delivery) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.handle(delivery)
	}()
}

func (r *liveReporter) Wait() {
	r.wg.Wait()
}

func (r *liveReporter) handle(delivery listener.Delivery) {
	// Serializing diagnostics keeps terminal output deterministic and avoids
	// depending on undocumented concurrency guarantees of embedded rule engines.
	r.mu.Lock()
	defer r.mu.Unlock()

	writeLiveDeliveryHeader(r.stdout, delivery)
	if delivery.ForwardError != nil {
		fmt.Fprintf(r.stderr, "wirelint: forward failed for trace %s: %v\n", delivery.Trace.TraceID, delivery.ForwardError)
	}

	if r.saveDir != "" {
		path, err := saveTraceAtomic(r.saveDir, delivery.Trace)
		if err != nil {
			fmt.Fprintf(r.stderr, "wirelint: save trace %s: %v\n", delivery.Trace.TraceID, err)
		} else {
			fmt.Fprintf(r.stdout, "Saved Trace: %s\n", path)
		}
	}

	report, err := r.evaluator.Evaluate(delivery.Trace, r.pack)
	if err != nil {
		fmt.Fprintf(r.stderr, "wirelint: evaluate live trace %s: %v\n", delivery.Trace.TraceID, err)
		return
	}
	writeStyledTextReport(r.stdout, report)
	fmt.Fprintln(r.stdout)
}

func writeLiveDeliveryHeader(w io.Writer, delivery listener.Delivery) {
	trace := delivery.Trace
	if len(trace.Envelopes) == 0 {
		fmt.Fprintf(w, "\nDelivery %s\n", trace.TraceID)
		return
	}
	envelope := trace.Envelopes[0]
	path := envelope.Request.URL
	if parsed, err := url.Parse(envelope.Request.URL); err == nil {
		path = parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
	}
	if envelope.Response != nil {
		fmt.Fprintf(w, "\nDelivery %s · %s %s -> HTTP %d · %.1fms\n", trace.TraceID, envelope.Request.Method, path, envelope.Response.Status, envelope.Response.DurationMS)
		return
	}
	fmt.Fprintf(w, "\nDelivery %s · %s %s -> forward failed\n", trace.TraceID, envelope.Request.Method, path)
}

func saveTraceAtomic(dir string, trace model.Trace) (string, error) {
	if !safeTraceID.MatchString(trace.TraceID) {
		return "", fmt.Errorf("unsafe trace id %q", trace.TraceID)
	}
	payload, err := json.MarshalIndent(trace, "", "  ")
	if err != nil {
		return "", err
	}
	payload = append(payload, '\n')

	temp, err := os.CreateTemp(dir, ".wirelint-trace-*.tmp")
	if err != nil {
		return "", err
	}
	tempName := temp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tempName)
		}
	}()

	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return "", err
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return "", err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return "", err
	}
	if err := temp.Close(); err != nil {
		return "", err
	}

	finalPath := filepath.Join(dir, trace.TraceID+".json")
	if _, err := os.Stat(finalPath); err == nil {
		return "", fmt.Errorf("trace file already exists: %s", finalPath)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Rename(tempName, finalPath); err != nil {
		return "", err
	}
	cleanup = false
	return finalPath, nil
}

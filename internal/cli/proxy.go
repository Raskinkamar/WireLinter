package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/Raskinkamar/WireLinter/internal/engine"
	"github.com/Raskinkamar/WireLinter/internal/model"
	"github.com/Raskinkamar/WireLinter/internal/pack"
	outboundproxy "github.com/Raskinkamar/WireLinter/internal/proxy"
)

func runProxy(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runProxyContext(ctx, args, stdout, stderr)
}

func runProxyContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runProxyContextWithReady(ctx, args, stdout, stderr, nil)
}

func runProxyContextWithReady(ctx context.Context, args []string, stdout, stderr io.Writer, readyHook func(net.Addr)) int {
	args = normalizeProxyArgs(args)
	flags := flag.NewFlagSet("proxy", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var provider string
	var packDir string
	var target string
	var address string
	var saveDir string
	var allowPublicListen bool
	var maxBodyBytes int64
	var maxResponseCaptureBytes int64

	flags.StringVar(&provider, "provider", "", "bundled official provider pack")
	flags.StringVar(&packDir, "pack", "", "external provider pack directory")
	flags.StringVar(&target, "target", "", "upstream provider base URL, for example https://api.github.com")
	flags.StringVar(&address, "addr", outboundproxy.DefaultListenAddress, "local proxy address")
	flags.StringVar(&saveDir, "save-dir", "", "optional directory for canonical Trace JSON files")
	flags.BoolVar(&allowPublicListen, "allow-public-listen", false, "allow binding the proxy to a non-loopback interface")
	flags.Int64Var(&maxBodyBytes, "max-body-bytes", outboundproxy.DefaultMaxRequestBodyBytes, "maximum outbound request body size")
	flags.Int64Var(&maxResponseCaptureBytes, "max-response-capture-bytes", outboundproxy.DefaultMaxResponseCaptureBytes, "maximum provider response bytes retained in Trace evidence")

	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "wirelint proxy: positional arguments are not supported")
		return 2
	}
	if err := validatePackSelection(provider, packDir); err != nil {
		fmt.Fprintf(stderr, "wirelint proxy: %v\n", err)
		return 2
	}
	if strings.TrimSpace(target) == "" {
		fmt.Fprintln(stderr, "wirelint proxy: upstream provider URL is required (--target is required in explicit form)")
		fmt.Fprintln(stderr, "try: wirelint proxy <provider> <upstream-url>")
		return 2
	}
	if maxBodyBytes <= 0 {
		fmt.Fprintln(stderr, "wirelint proxy: --max-body-bytes must be greater than zero")
		return 2
	}
	if maxResponseCaptureBytes <= 0 {
		fmt.Fprintln(stderr, "wirelint proxy: --max-response-capture-bytes must be greater than zero")
		return 2
	}
	if err := outboundproxy.ValidateListenAddress(address, allowPublicListen); err != nil {
		fmt.Fprintf(stderr, "wirelint proxy: %v\n", err)
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
	reporter, err := newProxyReporter(proxyReporterConfig{
		Evaluator: evaluator,
		Pack:      loaded,
		Stdout:    stdout,
		Stderr:    stderr,
		SaveDir:   saveDir,
	})
	if err != nil {
		return executionError(stderr, "initialize proxy reporter", err)
	}

	localProxy, err := outboundproxy.New(outboundproxy.Config{
		Provider:                loaded.Manifest.ID,
		Target:                  target,
		MaxRequestBodyBytes:     maxBodyBytes,
		MaxResponseCaptureBytes: maxResponseCaptureBytes,
		OnExchange:              reporter.Enqueue,
	})
	if err != nil {
		return executionError(stderr, "initialize outbound proxy", err)
	}

	warnMissingSecrets(stderr, loaded.Manifest.Secrets)

	serveErr := localProxy.Serve(ctx, address, allowPublicListen, func(actual net.Addr) {
		fmt.Fprintf(stdout, "WireLinter proxy listening on http://%s/\n", displayProxyAddress(actual))
		fmt.Fprintf(stdout, "Provider: %s\n", loaded.Manifest.ID)
		fmt.Fprintf(stdout, "Upstream: %s\n", localProxy.Target())
		if strings.TrimSpace(saveDir) == "" {
			fmt.Fprintln(stdout, "Trace persistence: off")
		} else {
			fmt.Fprintf(stdout, "Trace persistence: %s\n", reporter.saveDir)
		}
		fmt.Fprintln(stdout, "Sensitive header and query values are redacted in Trace evidence.")
		fmt.Fprintln(stdout, "Press Ctrl+C to stop.")
		fmt.Fprintln(stdout)
		if readyHook != nil {
			readyHook(actual)
		}
	})

	reporter.Wait()
	if serveErr != nil {
		return executionError(stderr, "proxy stopped unexpectedly", serveErr)
	}
	return 0
}

func normalizeProxyArgs(args []string) []string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return args
	}
	normalized := []string{"--provider", args[0]}
	rest := args[1:]
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		normalized = append(normalized, "--target", rest[0])
		rest = rest[1:]
	}
	return append(normalized, rest...)
}

func displayProxyAddress(address net.Addr) string {
	if address == nil {
		return outboundproxy.DefaultListenAddress
	}
	return address.String()
}

type proxyReporterConfig struct {
	Evaluator *engine.Evaluator
	Pack      *pack.Loaded
	Stdout    io.Writer
	Stderr    io.Writer
	SaveDir   string
}

type proxyReporter struct {
	evaluator *engine.Evaluator
	pack      *pack.Loaded
	stdout    io.Writer
	stderr    io.Writer
	saveDir   string

	mu sync.Mutex
	wg sync.WaitGroup
}

func newProxyReporter(config proxyReporterConfig) (*proxyReporter, error) {
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

	return &proxyReporter{
		evaluator: config.Evaluator,
		pack:      config.Pack,
		stdout:    config.Stdout,
		stderr:    config.Stderr,
		saveDir:   saveDir,
	}, nil
}

func (r *proxyReporter) Enqueue(exchange outboundproxy.Exchange) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.handle(exchange)
	}()
}

func (r *proxyReporter) Wait() {
	r.wg.Wait()
}

func (r *proxyReporter) handle(exchange outboundproxy.Exchange) {
	r.mu.Lock()
	defer r.mu.Unlock()

	writeProxyExchangeHeader(r.stdout, exchange.Trace)
	if exchange.ForwardError != nil {
		fmt.Fprintf(r.stderr, "wirelint: upstream request failed for trace %s: %v\n", exchange.Trace.TraceID, exchange.ForwardError)
	}

	if r.saveDir != "" {
		path, err := saveTraceAtomic(r.saveDir, exchange.Trace)
		if err != nil {
			fmt.Fprintf(r.stderr, "wirelint: save trace %s: %v\n", exchange.Trace.TraceID, err)
		} else {
			fmt.Fprintf(r.stdout, "Saved Trace: %s\n", path)
		}
	}

	report, err := r.evaluator.Evaluate(exchange.Trace, r.pack)
	if err != nil {
		fmt.Fprintf(r.stderr, "wirelint: evaluate proxy trace %s: %v\n", exchange.Trace.TraceID, err)
		return
	}
	writeStyledTextReport(r.stdout, report)
	fmt.Fprintln(r.stdout)
}

func writeProxyExchangeHeader(w io.Writer, trace model.Trace) {
	if len(trace.Envelopes) == 0 {
		fmt.Fprintf(w, "\nExchange %s\n", trace.TraceID)
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
		fmt.Fprintf(w, "\nExchange %s · %s %s -> HTTP %d · %.1fms\n", trace.TraceID, envelope.Request.Method, path, envelope.Response.Status, envelope.Response.DurationMS)
		return
	}
	fmt.Fprintf(w, "\nExchange %s · %s %s -> upstream failed\n", trace.TraceID, envelope.Request.Method, path)
}

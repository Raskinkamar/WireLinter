package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

const (
	DefaultListenAddress           = "127.0.0.1:4546"
	DefaultMaxRequestBodyBytes     = int64(16 << 20)
	DefaultMaxResponseCaptureBytes = int64(1 << 20)
	DefaultReadHeaderTimeout       = 5 * time.Second
	DefaultRequestReadTimeout      = 20 * time.Second
	DefaultForwardTimeout          = 30 * time.Second
	DefaultIdleTimeout             = 60 * time.Second
	DefaultShutdownTimeout         = 5 * time.Second
	DefaultMaxHeaderBytes          = 1 << 20
)

type Config struct {
	Provider                string
	Target                  string
	MaxRequestBodyBytes     int64
	MaxResponseCaptureBytes int64
	RequestReadTimeout      time.Duration
	ForwardTimeout          time.Duration
	OnExchange              func(Exchange)
}

type Exchange struct {
	Trace        model.Trace
	ForwardError error
}

type Proxy struct {
	provider                string
	target                  *url.URL
	maxRequestBodyBytes     int64
	maxResponseCaptureBytes int64
	requestReadTimeout      time.Duration
	forwardTimeout          time.Duration
	client                  *http.Client
	onExchange              func(Exchange)
}

func New(config Config) (*Proxy, error) {
	provider := strings.TrimSpace(config.Provider)
	if provider == "" {
		return nil, fmt.Errorf("provider is required")
	}
	target, err := validateTarget(config.Target)
	if err != nil {
		return nil, err
	}

	maxRequest := config.MaxRequestBodyBytes
	if maxRequest <= 0 {
		maxRequest = DefaultMaxRequestBodyBytes
	}
	maxResponse := config.MaxResponseCaptureBytes
	if maxResponse <= 0 {
		maxResponse = DefaultMaxResponseCaptureBytes
	}
	readTimeout := config.RequestReadTimeout
	if readTimeout <= 0 {
		readTimeout = DefaultRequestReadTimeout
	}
	forwardTimeout := config.ForwardTimeout
	if forwardTimeout <= 0 {
		forwardTimeout = DefaultForwardTimeout
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.ResponseHeaderTimeout = forwardTimeout
	transport.IdleConnTimeout = 30 * time.Second
	transport.MaxIdleConns = 16
	transport.MaxIdleConnsPerHost = 16

	client := &http.Client{
		Transport: transport,
		Timeout:   forwardTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Proxy{
		provider:                provider,
		target:                  target,
		maxRequestBodyBytes:     maxRequest,
		maxResponseCaptureBytes: maxResponse,
		requestReadTimeout:      readTimeout,
		forwardTimeout:          forwardTimeout,
		client:                  client,
		onExchange:              config.OnExchange,
	}, nil
}

func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(p.serveHTTP)
}

func (p *Proxy) Target() string {
	return p.target.String()
}

func (p *Proxy) Serve(ctx context.Context, address string, allowPublicListen bool, ready func(net.Addr)) error {
	if ctx == nil {
		return fmt.Errorf("serve context is nil")
	}
	if strings.TrimSpace(address) == "" {
		address = DefaultListenAddress
	}
	if err := ValidateListenAddress(address, allowPublicListen); err != nil {
		return err
	}

	networkListener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}

	server := &http.Server{
		Handler:           p.Handler(),
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       p.requestReadTimeout,
		WriteTimeout:      p.forwardTimeout + 10*time.Second,
		IdleTimeout:       DefaultIdleTimeout,
		MaxHeaderBytes:    DefaultMaxHeaderBytes,
	}

	if ready != nil {
		ready(networkListener.Addr())
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(networkListener)
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), DefaultShutdownTimeout)
		defer cancel()
		shutdownErr := server.Shutdown(shutdownCtx)
		serveErr := <-errCh
		if shutdownErr != nil {
			return fmt.Errorf("proxy shutdown: %w", shutdownErr)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return serveErr
		}
		return nil
	}
}

func ValidateListenAddress(address string, allowPublic bool) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", address, err)
	}
	if allowPublic {
		return nil
	}
	if isLoopbackHost(host) {
		return nil
	}
	if host == "" {
		return fmt.Errorf("listen address %q binds all interfaces; use an explicit loopback address or opt in to public listening", address)
	}
	return fmt.Errorf("listen host %q is not loopback; public listening requires explicit opt-in", host)
}

func validateTarget(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("target is required")
	}
	target, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("target scheme must be http or https")
	}
	if target.Host == "" {
		return nil, fmt.Errorf("target must have a host")
	}
	if target.User != nil {
		return nil, fmt.Errorf("target must not contain userinfo")
	}
	if target.Fragment != "" {
		return nil, fmt.Errorf("target must not contain a fragment")
	}
	if target.RawQuery != "" || target.ForceQuery {
		return nil, fmt.Errorf("target must not contain a query string; client request query is forwarded")
	}
	if target.Path == "" {
		target.Path = "/"
	}
	return target, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	startedAt := time.Now().UTC()
	traceID, err := randomID("trace")
	if err != nil {
		http.Error(w, "wirelint: failed to create trace id", http.StatusInternalServerError)
		return
	}
	envelopeID, err := randomID("env")
	if err != nil {
		http.Error(w, "wirelint: failed to create envelope id", http.StatusInternalServerError)
		return
	}

	limitedBody := http.MaxBytesReader(w, r.Body, p.maxRequestBodyBytes)
	body, err := io.ReadAll(limitedBody)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, fmt.Sprintf("wirelint: request body exceeds %d bytes", tooLarge.Limit), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "wirelint: failed to read request body", http.StatusBadRequest)
		return
	}
	body = append([]byte{}, body...)

	upstreamURL, err := joinTargetURL(p.target, r.URL)
	if err != nil {
		http.Error(w, "wirelint: invalid upstream request URL", http.StatusBadRequest)
		return
	}
	outbound, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "wirelint: failed to build upstream request", http.StatusBadRequest)
		return
	}
	outbound.Header = forwardingHeaders(r.Header)
	// Make the semantic Host evidence explicit. net/http would send URL.Host
	// when Request.Host is empty, but recording it here avoids confusing the
	// local proxy host with the actual provider host in captured evidence.
	outbound.Host = upstreamURL.Host

	queryRaw, queryItems, queryFidelity := sanitizeQuery(upstreamURL.RawQuery)
	evidenceURL := *upstreamURL
	evidenceURL.RawQuery = queryRaw
	evidenceURL.ForceQuery = upstreamURL.ForceQuery && queryRaw == ""
	bodyHash := sha256.Sum256(body)
	requestEvidence := model.HTTPRequest{
		Method:              outbound.Method,
		URL:                 evidenceURL.String(),
		Headers:             redactHeaders(semanticRequestHeaders(outbound)),
		HeadersCompleteness: "complete",
		RawQuery:            queryRaw,
		QueryFidelity:       queryFidelity,
		Query:               queryItems,
		BodyFidelity:        "exact",
		RawBodyBase64:       body,
		BodySHA256:          hex.EncodeToString(bodyHash[:]),
		DecodedBody:         decodeJSONBody(body),
	}

	trace := model.Trace{
		SchemaVersion: 1,
		TraceID:       traceID,
		Provider:      p.provider,
		StartedAt:     startedAt,
		Envelopes: []model.Envelope{{
			ID:         envelopeID,
			Provider:   p.provider,
			Direction:  "outbound",
			ReceivedAt: startedAt,
			Request:    requestEvidence,
			Metadata: map[string]any{
				"captureSource":      "wirelint-proxy",
				"requestHeaderModel": "semantic-redacted",
			},
		}},
		Observations: []model.Observation{{
			ID:         traceID + "-request",
			Type:       "request.sent",
			At:         startedAt,
			EnvelopeID: envelopeID,
		}},
		Metadata: map[string]any{
			"acquisition": "proxy",
			"target":      p.target.String(),
		},
	}

	response, err := p.client.Do(outbound)
	if err != nil {
		p.finishForwardFailure(w, &trace, envelopeID, err)
		return
	}
	defer response.Body.Close()

	for key, values := range responseHeadersForSender(response.Header) {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)

	capture := newBoundedCapture(p.maxResponseCaptureBytes)
	responseHash := sha256.New()
	readComplete := false
	writeOK := true
	buffer := make([]byte, 32<<10)
	for {
		n, readErr := response.Body.Read(buffer)
		if n > 0 {
			chunk := buffer[:n]
			_, _ = responseHash.Write(chunk)
			capture.Write(chunk)
			if writeOK {
				if _, writeErr := w.Write(chunk); writeErr != nil {
					writeOK = false
				}
			}
		}
		if errors.Is(readErr, io.EOF) {
			readComplete = true
			break
		}
		if readErr != nil {
			break
		}
	}

	completedAt := time.Now().UTC()
	responseEvidence := &model.HTTPResponse{
		Status:              response.StatusCode,
		Protocol:            response.Proto,
		Headers:             redactHeaders(semanticResponseHeaders(response)),
		HeadersCompleteness: "complete",
		BodyFidelity:        "unavailable",
		RawBodyBase64:       nil,
		DurationMS:          float64(completedAt.Sub(startedAt).Microseconds()) / 1000,
	}
	if readComplete {
		responseEvidence.BodySHA256 = hex.EncodeToString(responseHash.Sum(nil))
		if !capture.Overflowed() {
			responseEvidence.BodyFidelity = "exact"
			responseEvidence.RawBodyBase64 = capture.Bytes()
			responseEvidence.DecodedBody = decodeJSONBody(responseEvidence.RawBodyBase64)
		}
	}
	trace.Envelopes[0].Response = responseEvidence
	trace.Observations = append(trace.Observations, model.Observation{
		ID:         traceID + "-response",
		Type:       "response.received",
		At:         completedAt,
		EnvelopeID: envelopeID,
		Attributes: map[string]any{
			"status":          response.StatusCode,
			"durationMs":      responseEvidence.DurationMS,
			"bodyCaptured":    responseEvidence.BodyFidelity == "exact",
			"clientWriteOkay": writeOK,
		},
	})
	trace.EndedAt = &completedAt
	p.deliver(Exchange{Trace: trace})
}

func (p *Proxy) finishForwardFailure(w http.ResponseWriter, trace *model.Trace, envelopeID string, forwardErr error) {
	completedAt := time.Now().UTC()
	trace.Observations = append(trace.Observations, model.Observation{
		ID:         trace.TraceID + "-forward-failed",
		Type:       "forward.failed",
		At:         completedAt,
		EnvelopeID: envelopeID,
		Attributes: map[string]any{"error": forwardErr.Error()},
	})
	trace.EndedAt = &completedAt
	http.Error(w, "wirelint: upstream provider is unavailable", http.StatusBadGateway)
	p.deliver(Exchange{Trace: *trace, ForwardError: forwardErr})
}

func (p *Proxy) deliver(exchange Exchange) {
	if p.onExchange != nil {
		p.onExchange(exchange)
	}
}

func joinTargetURL(base, incoming *url.URL) (*url.URL, error) {
	if base == nil || incoming == nil {
		return nil, fmt.Errorf("base and incoming URLs are required")
	}
	result := *base
	baseEscaped := base.EscapedPath()
	incomingEscaped := incoming.EscapedPath()
	if incomingEscaped == "" {
		incomingEscaped = "/"
	}
	var joinedEscaped string
	switch {
	case baseEscaped == "" || baseEscaped == "/":
		joinedEscaped = "/" + strings.TrimPrefix(incomingEscaped, "/")
	case incomingEscaped == "/":
		joinedEscaped = strings.TrimSuffix(baseEscaped, "/") + "/"
	default:
		joinedEscaped = strings.TrimSuffix(baseEscaped, "/") + "/" + strings.TrimPrefix(incomingEscaped, "/")
	}
	joinedPath, err := url.PathUnescape(joinedEscaped)
	if err != nil {
		return nil, fmt.Errorf("decode joined path: %w", err)
	}
	result.Path = joinedPath
	result.RawPath = joinedEscaped
	if result.EscapedPath() == result.Path {
		result.RawPath = ""
	}
	result.RawQuery = incoming.RawQuery
	result.ForceQuery = incoming.ForceQuery
	return &result, nil
}

func randomID(prefix string) (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}

type boundedCapture struct {
	limit    int64
	buffer   bytes.Buffer
	overflow bool
}

func newBoundedCapture(limit int64) *boundedCapture {
	return &boundedCapture{limit: limit}
}

func (c *boundedCapture) Write(p []byte) {
	if c.overflow {
		return
	}
	if int64(c.buffer.Len()+len(p)) > c.limit {
		c.overflow = true
		c.buffer.Reset()
		return
	}
	_, _ = c.buffer.Write(p)
}

func (c *boundedCapture) Overflowed() bool {
	return c.overflow
}

func (c *boundedCapture) Bytes() []byte {
	if c.overflow {
		return nil
	}
	if c.buffer.Len() == 0 {
		return []byte{}
	}
	return append([]byte{}, c.buffer.Bytes()...)
}

package listener

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

const (
	DefaultListenAddress          = "127.0.0.1:4545"
	DefaultMaxRequestBodyBytes    = int64(16 << 20)
	DefaultMaxResponseCaptureBytes = int64(1 << 20)
	DefaultReadHeaderTimeout      = 5 * time.Second
	DefaultRequestReadTimeout     = 20 * time.Second
	DefaultForwardTimeout         = 30 * time.Second
	DefaultIdleTimeout            = 60 * time.Second
	DefaultShutdownTimeout        = 5 * time.Second
	DefaultMaxHeaderBytes         = 1 << 20
)

type Config struct {
	Provider                string
	ForwardTo               string
	AllowRemoteForward      bool
	MaxRequestBodyBytes     int64
	MaxResponseCaptureBytes int64
	RequestReadTimeout      time.Duration
	ForwardTimeout          time.Duration
	OnDelivery              func(Delivery)
}

type Delivery struct {
	Trace        model.Trace
	ForwardError error
}

type Listener struct {
	provider                string
	target                  *url.URL
	maxRequestBodyBytes     int64
	maxResponseCaptureBytes int64
	requestReadTimeout      time.Duration
	forwardTimeout          time.Duration
	client                  *http.Client
	onDelivery              func(Delivery)
}

func New(config Config) (*Listener, error) {
	provider := strings.TrimSpace(config.Provider)
	if provider == "" {
		return nil, fmt.Errorf("provider is required")
	}
	target, err := validateForwardTarget(config.ForwardTo, config.AllowRemoteForward)
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

	return &Listener{
		provider:                provider,
		target:                  target,
		maxRequestBodyBytes:     maxRequest,
		maxResponseCaptureBytes: maxResponse,
		requestReadTimeout:      readTimeout,
		forwardTimeout:          forwardTimeout,
		client:                  client,
		onDelivery:              config.OnDelivery,
	}, nil
}

func (l *Listener) Handler() http.Handler {
	return http.HandlerFunc(l.serveHTTP)
}

func (l *Listener) Target() string {
	return l.target.String()
}

func (l *Listener) Serve(ctx context.Context, address string, allowPublicListen bool, ready func(net.Addr)) error {
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
		Handler:           l.Handler(),
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       l.requestReadTimeout,
		WriteTimeout:      l.forwardTimeout + 10*time.Second,
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
			return fmt.Errorf("listener shutdown: %w", shutdownErr)
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

func validateForwardTarget(raw string, allowRemote bool) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("forward target is required")
	}
	target, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse forward target: %w", err)
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("forward target scheme must be http or https")
	}
	if target.Host == "" {
		return nil, fmt.Errorf("forward target must have a host")
	}
	if target.User != nil {
		return nil, fmt.Errorf("forward target must not contain userinfo")
	}
	if target.Fragment != "" {
		return nil, fmt.Errorf("forward target must not contain a fragment")
	}
	if target.RawQuery != "" || target.ForceQuery {
		return nil, fmt.Errorf("forward target must not contain a query string; inbound webhook query is forwarded exactly")
	}
	if !allowRemote && !isLoopbackHost(target.Hostname()) {
		return nil, fmt.Errorf("forward host %q is not loopback; remote forwarding requires explicit opt-in", target.Hostname())
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

func (l *Listener) serveHTTP(w http.ResponseWriter, r *http.Request) {
	receivedAt := time.Now().UTC()
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

	limitedBody := http.MaxBytesReader(w, r.Body, l.maxRequestBodyBytes)
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

	requestURL, err := absoluteRequestURL(r)
	if err != nil {
		http.Error(w, "wirelint: invalid inbound request URL", http.StatusBadRequest)
		return
	}
	queryItems, queryDecoded := decodeOrderedQuery(r.URL.RawQuery)
	requestHeaders := semanticRequestHeaders(r)
	bodyHash := sha256.Sum256(body)

	requestEvidence := model.HTTPRequest{
		Method:              r.Method,
		URL:                 requestURL,
		Protocol:            r.Proto,
		Headers:             requestHeaders,
		HeadersCompleteness: "complete",
		RawQuery:            r.URL.RawQuery,
		QueryFidelity:       "exact",
		BodyFidelity:        "exact",
		RawBodyBase64:       body,
		BodySHA256:          hex.EncodeToString(bodyHash[:]),
		DecodedBody:         decodeJSONBody(body),
	}
	if queryDecoded {
		requestEvidence.Query = queryItems
	}

	trace := model.Trace{
		SchemaVersion: 1,
		TraceID:       traceID,
		Provider:      l.provider,
		StartedAt:     receivedAt,
		Envelopes: []model.Envelope{{
			ID:         envelopeID,
			Provider:   l.provider,
			ReceivedAt: receivedAt,
			Request:    requestEvidence,
			Metadata: map[string]any{
				"captureSource":          "go-net-http",
				"requestHeaderModel":     "semantic",
				"requestTrailersObserved": len(r.Trailer),
			},
		}},
		Observations: []model.Observation{{
			ID:         traceID + "-request",
			Type:       "request.received",
			At:         receivedAt,
			EnvelopeID: envelopeID,
		}},
		Metadata: map[string]any{
			"acquisition": "listen",
			"forwardTo":   l.target.String(),
		},
	}

	outboundURL := *l.target
	outboundURL.RawQuery = r.URL.RawQuery
	outboundURL.ForceQuery = r.URL.ForceQuery
	outbound, err := http.NewRequestWithContext(r.Context(), r.Method, outboundURL.String(), bytes.NewReader(body))
	if err != nil {
		l.finishForwardFailure(w, &trace, envelopeID, fmt.Errorf("build forwarded request: %w", err))
		return
	}
	outbound.Header = forwardingHeaders(r.Header)

	response, err := l.client.Do(outbound)
	if err != nil {
		l.finishForwardFailure(w, &trace, envelopeID, err)
		return
	}
	defer response.Body.Close()

	for key, values := range responseHeadersForSender(response.Header) {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)

	capture := newBoundedCapture(l.maxResponseCaptureBytes)
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
		Headers:             semanticResponseHeaders(response),
		HeadersCompleteness: "complete",
		BodyFidelity:        "unavailable",
		RawBodyBase64:       nil,
		DurationMS:          float64(completedAt.Sub(receivedAt).Microseconds()) / 1000,
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
			"senderWriteOkay": writeOK,
		},
	})
	trace.EndedAt = &completedAt
	l.deliver(Delivery{Trace: trace})
}

func (l *Listener) finishForwardFailure(w http.ResponseWriter, trace *model.Trace, envelopeID string, forwardErr error) {
	completedAt := time.Now().UTC()
	trace.Observations = append(trace.Observations, model.Observation{
		ID:         trace.TraceID + "-forward-failed",
		Type:       "forward.failed",
		At:         completedAt,
		EnvelopeID: envelopeID,
		Attributes: map[string]any{"error": forwardErr.Error()},
	})
	trace.EndedAt = &completedAt
	http.Error(w, "wirelint: local application is unavailable", http.StatusBadGateway)
	l.deliver(Delivery{Trace: *trace, ForwardError: forwardErr})
}

func (l *Listener) deliver(delivery Delivery) {
	if l.onDelivery != nil {
		l.onDelivery(delivery)
	}
}

func absoluteRequestURL(r *http.Request) (string, error) {
	if r.Host == "" {
		return "", fmt.Errorf("request host is empty")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	u := url.URL{
		Scheme:   scheme,
		Host:     r.Host,
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
		ForceQuery: r.URL.ForceQuery,
	}
	return u.String(), nil
}

func decodeOrderedQuery(raw string) ([]model.QueryItem, bool) {
	if raw == "" {
		return []model.QueryItem{}, true
	}
	parts := strings.Split(raw, "&")
	items := make([]model.QueryItem, 0, len(parts))
	for _, part := range parts {
		nameRaw, valueRaw, found := strings.Cut(part, "=")
		if !found {
			valueRaw = ""
		}
		name, err := url.QueryUnescape(nameRaw)
		if err != nil {
			return nil, false
		}
		value, err := url.QueryUnescape(valueRaw)
		if err != nil {
			return nil, false
		}
		items = append(items, model.QueryItem{Name: name, Value: value})
	}
	return items, true
}

func decodeJSONBody(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil
	}
	return value
}

func semanticRequestHeaders(r *http.Request) []model.Header {
	headers := semanticHeaders(r.Header)
	if r.Host != "" {
		headers = append(headers, model.Header{Name: "Host", Value: r.Host})
	}
	if r.ContentLength > 0 && !containsHeader(headers, "Content-Length") {
		headers = append(headers, model.Header{Name: "Content-Length", Value: strconv.FormatInt(r.ContentLength, 10)})
	}
	if len(r.TransferEncoding) > 0 && !containsHeader(headers, "Transfer-Encoding") {
		headers = append(headers, model.Header{Name: "Transfer-Encoding", Value: strings.Join(r.TransferEncoding, ", ")})
	}
	return headers
}

func semanticResponseHeaders(response *http.Response) []model.Header {
	headers := semanticHeaders(response.Header)
	if response.ContentLength > 0 && !containsHeader(headers, "Content-Length") {
		headers = append(headers, model.Header{Name: "Content-Length", Value: strconv.FormatInt(response.ContentLength, 10)})
	}
	if len(response.TransferEncoding) > 0 && !containsHeader(headers, "Transfer-Encoding") {
		headers = append(headers, model.Header{Name: "Transfer-Encoding", Value: strings.Join(response.TransferEncoding, ", ")})
	}
	return headers
}

func semanticHeaders(header http.Header) []model.Header {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]model.Header, 0, len(header))
	for _, key := range keys {
		for _, value := range header[key] {
			out = append(out, model.Header{Name: key, Value: value})
		}
	}
	return out
}

func containsHeader(headers []model.Header, name string) bool {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return true
		}
	}
	return false
}

func forwardingHeaders(in http.Header) http.Header {
	out := in.Clone()
	removeHopByHopHeaders(out)
	out.Del("Forwarded")
	out.Del("X-Forwarded-For")
	out.Del("X-Forwarded-Host")
	out.Del("X-Forwarded-Proto")
	return out
}

func responseHeadersForSender(in http.Header) http.Header {
	out := in.Clone()
	removeHopByHopHeaders(out)
	return out
}

func removeHopByHopHeaders(header http.Header) {
	for _, connection := range header.Values("Connection") {
		for _, token := range strings.Split(connection, ",") {
			if token = strings.TrimSpace(token); token != "" {
				header.Del(token)
			}
		}
	}
	for _, name := range []string{
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(name)
	}
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

package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

func TestProxyForwardsOutboundRequestAndCapturesUpstreamTrace(t *testing.T) {
	payload := []byte(`{"query":"query Viewer { viewer { login } }","variables":{"limit":1}}`)
	responseBody := []byte(`{"data":{"viewer":{"login":"octocat"}}}`)
	targetRequests := make(chan *http.Request, 1)
	targetBodies := make(chan []byte, 1)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("target read body: %v", err)
			return
		}
		targetRequests <- r.Clone(r.Context())
		targetBodies <- body
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=server-secret")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseBody)
	}))
	defer target.Close()

	exchanges := make(chan Exchange, 1)
	outboundProxy, err := New(Config{
		Provider: "github-graphql-api",
		Target:   target.URL + "/api",
		OnExchange: func(exchange Exchange) {
			exchanges <- exchange
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(outboundProxy.Handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPost, server.URL+"/graphql?access_token=query-secret&mode=test", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer ghp_super_secret")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	gotResponseBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Equal(gotResponseBody, responseBody) {
		t.Fatalf("proxy response = status %d body %q", resp.StatusCode, gotResponseBody)
	}
	if resp.Header.Get("Set-Cookie") != "session=server-secret" {
		t.Fatalf("client response did not preserve upstream Set-Cookie")
	}

	select {
	case observed := <-targetRequests:
		if observed.Method != http.MethodPost || observed.URL.Path != "/api/graphql" {
			t.Fatalf("upstream request = %s %s", observed.Method, observed.URL.Path)
		}
		if observed.URL.RawQuery != "access_token=query-secret&mode=test" {
			t.Fatalf("upstream raw query changed: %q", observed.URL.RawQuery)
		}
		if observed.Header.Get("Authorization") != "Bearer ghp_super_secret" {
			t.Fatalf("authorization was not forwarded exactly")
		}
		if observed.Header.Get("X-Forwarded-For") != "" {
			t.Fatalf("untrusted forwarding header leaked upstream")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive request")
	}
	select {
	case got := <-targetBodies:
		if !bytes.Equal(got, payload) {
			t.Fatalf("upstream body changed: got %q want %q", got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream body was not observed")
	}

	var exchange Exchange
	select {
	case exchange = <-exchanges:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not publish exchange")
	}
	if exchange.ForwardError != nil {
		t.Fatalf("unexpected forward error: %v", exchange.ForwardError)
	}
	if len(exchange.Trace.Envelopes) != 1 {
		t.Fatalf("unexpected trace: %#v", exchange.Trace)
	}
	envelope := exchange.Trace.Envelopes[0]
	if envelope.Direction != "outbound" {
		t.Fatalf("direction = %q", envelope.Direction)
	}
	if strings.Contains(envelope.Request.URL, "query-secret") || strings.Contains(envelope.Request.RawQuery, "query-secret") {
		t.Fatalf("query secret leaked into trace: %#v", envelope.Request)
	}
	if envelope.Request.QueryFidelity != "reconstructed" || len(envelope.Request.Query) != 2 || !envelope.Request.Query[0].Redacted {
		t.Fatalf("redacted query evidence = %#v", envelope.Request.Query)
	}
	if got := headerValue(envelope.Request.Headers, "Authorization"); got != "Bearer <redacted>" {
		t.Fatalf("authorization evidence = %q", got)
	}
	if !headerRedacted(envelope.Request.Headers, "Authorization") {
		t.Fatal("authorization evidence was not marked redacted")
	}
	if envelope.Response == nil || !headerRedacted(envelope.Response.Headers, "Set-Cookie") {
		t.Fatalf("response sensitive header was not redacted: %#v", envelope.Response)
	}
	if !bytes.Equal(envelope.Request.RawBodyBase64, payload) || !bytes.Equal(envelope.Response.RawBodyBase64, responseBody) {
		t.Fatal("request or response body evidence lost exact bytes")
	}
	decoded, ok := envelope.Response.DecodedBody.(map[string]any)
	if !ok || decoded["data"] == nil {
		t.Fatalf("GraphQL JSON response was not decoded: %#v", envelope.Response.DecodedBody)
	}
}

func TestProxyDoesNotFollowUpstreamRedirects(t *testing.T) {
	var redirected atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	target := httptest.NewServer(mux)
	defer target.Close()

	exchanges := make(chan Exchange, 1)
	outboundProxy, err := New(Config{Provider: "test", Target: target.URL, OnExchange: func(e Exchange) { exchanges <- e }})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(outboundProxy.Handler())
	defer server.Close()

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(server.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want redirect", resp.StatusCode)
	}
	if redirected.Load() != 0 {
		t.Fatalf("proxy followed redirect %d times", redirected.Load())
	}
	select {
	case exchange := <-exchanges:
		if exchange.Trace.Envelopes[0].Response == nil || exchange.Trace.Envelopes[0].Response.Status != http.StatusTemporaryRedirect {
			t.Fatal("redirect was not captured as upstream response")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing exchange")
	}
}

func TestProxyRejectsPublicBindWithoutOptIn(t *testing.T) {
	if err := ValidateListenAddress("0.0.0.0:4546", false); err == nil || !strings.Contains(err.Error(), "public listening") {
		t.Fatalf("expected public-listen rejection, got %v", err)
	}
}

func TestSanitizeQueryPreservesExactNonSensitiveQuery(t *testing.T) {
	raw, items, fidelity := sanitizeQuery("a=1&b=a%2Bb")
	if raw != "a=1&b=a%2Bb" || fidelity != "exact" || len(items) != 2 || items[1].Value != "a+b" {
		t.Fatalf("unexpected query evidence: raw=%q fidelity=%q items=%#v", raw, fidelity, items)
	}
}

func headerValue(headers []model.Header, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value
		}
	}
	return ""
}

func headerRedacted(headers []model.Header, name string) bool {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Redacted
		}
	}
	return false
}

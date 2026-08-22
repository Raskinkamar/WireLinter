package listener

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type observedRequest struct {
	method       string
	path         string
	rawQuery     string
	host         string
	body         []byte
	signature    string
	forwardedFor string
}

func TestListenerForwardsExactBodyAndCapturesCanonicalTrace(t *testing.T) {
	payload := []byte("{\n  \"id\": \"evt_test\", \"amount\": 1000\n}\n")
	responseBody := []byte("{\"accepted\":true}")
	targetRequests := make(chan observedRequest, 1)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("target read body: %v", err)
			return
		}
		targetRequests <- observedRequest{
			method:       r.Method,
			path:         r.URL.Path,
			rawQuery:     r.URL.RawQuery,
			host:         r.Host,
			body:         body,
			signature:    r.Header.Get("Stripe-Signature"),
			forwardedFor: r.Header.Get("X-Forwarded-For"),
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-App", "test")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(responseBody)
	}))
	defer target.Close()

	deliveries := make(chan Delivery, 1)
	listener, err := New(Config{
		Provider:  "stripe",
		ForwardTo: target.URL + "/webhooks/stripe",
		OnDelivery: func(delivery Delivery) {
			deliveries <- delivery
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	inbound := httptest.NewServer(listener.Handler())
	defer inbound.Close()

	req, err := http.NewRequest(http.MethodPost, inbound.URL+"/incoming?foo=a%2Bb&foo=two", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Stripe-Signature", "t=1700000000,v1=deadbeef")
	req.Header.Set("X-Forwarded-For", "203.0.113.10")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	gotResponseBody, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("sender status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if !bytes.Equal(gotResponseBody, responseBody) {
		t.Fatalf("sender response body = %q, want %q", gotResponseBody, responseBody)
	}
	if resp.Header.Get("X-App") != "test" {
		t.Fatalf("sender did not receive application response header")
	}

	select {
	case observed := <-targetRequests:
		if observed.method != http.MethodPost || observed.path != "/webhooks/stripe" {
			t.Fatalf("forwarded request = %s %s", observed.method, observed.path)
		}
		if observed.rawQuery != "foo=a%2Bb&foo=two" {
			t.Fatalf("forwarded raw query = %q", observed.rawQuery)
		}
		if !bytes.Equal(observed.body, payload) {
			t.Fatalf("forwarded body changed:\n got %q\nwant %q", observed.body, payload)
		}
		if observed.signature != "t=1700000000,v1=deadbeef" {
			t.Fatalf("signature header was not preserved: %q", observed.signature)
		}
		if observed.forwardedFor != "" {
			t.Fatalf("untrusted X-Forwarded-For leaked to target: %q", observed.forwardedFor)
		}
		wantHost := strings.TrimPrefix(target.URL, "http://")
		if observed.host != wantHost {
			t.Fatalf("forwarded Host = %q, want target host %q", observed.host, wantHost)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("target did not receive forwarded request")
	}

	var delivery Delivery
	select {
	case delivery = <-deliveries:
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not publish a delivery")
	}
	if delivery.ForwardError != nil {
		t.Fatalf("unexpected forward error: %v", delivery.ForwardError)
	}
	if delivery.Trace.Provider != "stripe" || len(delivery.Trace.Envelopes) != 1 {
		t.Fatalf("unexpected trace shape: %#v", delivery.Trace)
	}
	envelope := delivery.Trace.Envelopes[0]
	if envelope.Request.BodyFidelity != "exact" || !bytes.Equal(envelope.Request.RawBodyBase64, payload) {
		t.Fatalf("request body evidence is not exact: %#v", envelope.Request)
	}
	if envelope.Request.RawQuery != "foo=a%2Bb&foo=two" || envelope.Request.QueryFidelity != "exact" {
		t.Fatalf("query evidence = raw %q fidelity %q", envelope.Request.RawQuery, envelope.Request.QueryFidelity)
	}
	if len(envelope.Request.Query) != 2 || envelope.Request.Query[0].Value != "a+b" || envelope.Request.Query[1].Value != "two" {
		t.Fatalf("decoded ordered query = %#v", envelope.Request.Query)
	}
	if envelope.Request.HeadersCompleteness != "complete" {
		t.Fatalf("request header completeness = %q", envelope.Request.HeadersCompleteness)
	}
	if envelope.Response == nil {
		t.Fatal("response evidence is missing")
	}
	if envelope.Response.Status != http.StatusAccepted || envelope.Response.BodyFidelity != "exact" || !bytes.Equal(envelope.Response.RawBodyBase64, responseBody) {
		t.Fatalf("unexpected response evidence: %#v", envelope.Response)
	}
	if delivery.Trace.EndedAt == nil || len(delivery.Trace.Observations) != 2 {
		t.Fatalf("trace lifecycle is incomplete: %#v", delivery.Trace)
	}
}

func TestListenerDoesNotFollowApplicationRedirects(t *testing.T) {
	var redirected atomic.Int32
	targetMux := http.NewServeMux()
	targetMux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusTemporaryRedirect)
	})
	targetMux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	target := httptest.NewServer(targetMux)
	defer target.Close()

	deliveries := make(chan Delivery, 1)
	listener, err := New(Config{Provider: "stripe", ForwardTo: target.URL + "/start", OnDelivery: func(d Delivery) { deliveries <- d }})
	if err != nil {
		t.Fatal(err)
	}
	inbound := httptest.NewServer(listener.Handler())
	defer inbound.Close()

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Post(inbound.URL+"/", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("sender status = %d, want redirect", resp.StatusCode)
	}
	if redirected.Load() != 0 {
		t.Fatalf("listener followed application redirect %d times", redirected.Load())
	}
	select {
	case delivery := <-deliveries:
		if delivery.Trace.Envelopes[0].Response == nil || delivery.Trace.Envelopes[0].Response.Status != http.StatusTemporaryRedirect {
			t.Fatalf("redirect was not recorded as the application response: %#v", delivery.Trace.Envelopes[0].Response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing delivery")
	}
}

func TestListenerRejectsOversizedRequestBeforeForwarding(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	listener, err := New(Config{Provider: "stripe", ForwardTo: target.URL, MaxRequestBodyBytes: 4})
	if err != nil {
		t.Fatal(err)
	}
	inbound := httptest.NewServer(listener.Handler())
	defer inbound.Close()

	resp, err := http.Post(inbound.URL+"/", "text/plain", strings.NewReader("12345"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("oversized request was forwarded %d times", targetCalls.Load())
	}
}

func TestListenerResponseCaptureOverflowDoesNotTruncateSenderResponse(t *testing.T) {
	responseBody := []byte("0123456789")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(responseBody)
	}))
	defer target.Close()

	deliveries := make(chan Delivery, 1)
	listener, err := New(Config{
		Provider:                "stripe",
		ForwardTo:               target.URL,
		MaxResponseCaptureBytes: 4,
		OnDelivery:              func(d Delivery) { deliveries <- d },
	})
	if err != nil {
		t.Fatal(err)
	}
	inbound := httptest.NewServer(listener.Handler())
	defer inbound.Close()

	resp, err := http.Post(inbound.URL+"/", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, responseBody) {
		t.Fatalf("sender response was truncated: got %q want %q", got, responseBody)
	}
	select {
	case delivery := <-deliveries:
		response := delivery.Trace.Envelopes[0].Response
		if response == nil {
			t.Fatal("response evidence missing")
		}
		if response.BodyFidelity != "unavailable" || response.RawBodyBase64 != nil {
			t.Fatalf("overflowing response incorrectly claims exact evidence: %#v", response)
		}
		if response.BodySHA256 == "" {
			t.Fatal("complete overflowing response should still retain its SHA-256")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing delivery")
	}
}

func TestListenerRecordsForwardFailureSeparately(t *testing.T) {
	deliveries := make(chan Delivery, 1)
	listener, err := New(Config{
		Provider:      "stripe",
		ForwardTo:     "http://127.0.0.1:1/webhook",
		ForwardTimeout: 500 * time.Millisecond,
		OnDelivery:    func(d Delivery) { deliveries <- d },
	})
	if err != nil {
		t.Fatal(err)
	}
	inbound := httptest.NewServer(listener.Handler())
	defer inbound.Close()

	resp, err := http.Post(inbound.URL+"/", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("sender status = %d, want 502", resp.StatusCode)
	}
	select {
	case delivery := <-deliveries:
		if delivery.ForwardError == nil {
			t.Fatal("forward failure was not surfaced operationally")
		}
		if len(delivery.Trace.Observations) != 2 || delivery.Trace.Observations[1].Type != "forward.failed" {
			t.Fatalf("forward failure observation missing: %#v", delivery.Trace.Observations)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("missing delivery")
	}
}

func TestListenerSafetyDefaults(t *testing.T) {
	if _, err := New(Config{Provider: "stripe", ForwardTo: "https://example.com/webhook"}); err == nil || !strings.Contains(err.Error(), "remote forwarding") {
		t.Fatalf("expected remote forwarding rejection, got %v", err)
	}
	if _, err := New(Config{Provider: "stripe", ForwardTo: "https://example.com/webhook", AllowRemoteForward: true}); err != nil {
		t.Fatalf("explicit remote forwarding opt-in rejected: %v", err)
	}
	if err := ValidateListenAddress("0.0.0.0:4545", false); err == nil || !strings.Contains(err.Error(), "public listening") {
		t.Fatalf("expected public listen rejection, got %v", err)
	}
	if err := ValidateListenAddress("0.0.0.0:4545", true); err != nil {
		t.Fatalf("explicit public-listen opt-in rejected: %v", err)
	}
	if err := ValidateListenAddress("127.0.0.1:4545", false); err != nil {
		t.Fatalf("loopback listen rejected: %v", err)
	}
}

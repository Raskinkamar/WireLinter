package cli

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

type synchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestListenCommandRunsRealStripeDeliveryThroughEngine(t *testing.T) {
	const secret = "whsec_live_listener_test"
	t.Setenv("STRIPE_WEBHOOK_SECRET", secret)

	payload := []byte("{\"id\":\"evt_live_listener\",\"object\":\"event\"}")
	targetRequests := make(chan []byte, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read target body: %v", err)
			return
		}
		targetRequests <- append([]byte{}, body...)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	saveDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stdout := &synchronizedBuffer{}
	stderr := &synchronizedBuffer{}
	ready := make(chan net.Addr, 1)
	done := make(chan int, 1)
	go func() {
		done <- runListenContextWithReady(ctx, []string{
			"--provider", "stripe",
			"--forward-to", target.URL + "/stripe",
			"--addr", "127.0.0.1:0",
			"--save-dir", saveDir,
		}, stdout, stderr, func(address net.Addr) {
			ready <- address
		})
	}()

	var address net.Addr
	select {
	case address = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatalf("listener did not become ready\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}

	timestamp := time.Now().Unix()
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))

	request, err := http.NewRequest(http.MethodPost, "http://"+address.String()+"/incoming?source=test", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=%s", timestamp, signature))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("listener response status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	select {
	case got := <-targetRequests:
		if !bytes.Equal(got, payload) {
			t.Fatalf("target body changed: got %q want %q", got, payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("local application did not receive forwarded request")
	}

	waitFor(t, 5*time.Second, func() bool {
		return strings.Contains(stdout.String(), "PASS WL-ST-SIGNATURE-001 [signature-valid]")
	}, func() string {
		return "live Stripe signature result was not emitted\nstdout:\n" + stdout.String() + "\nstderr:\n" + stderr.String()
	})

	var savedPath string
	waitFor(t, 5*time.Second, func() bool {
		matches, err := filepath.Glob(filepath.Join(saveDir, "trace_*.json"))
		if err != nil || len(matches) != 1 {
			return false
		}
		savedPath = matches[0]
		return true
	}, func() string { return "canonical live Trace was not saved" })

	raw, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved model.Trace
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("saved trace is invalid JSON: %v", err)
	}
	if saved.Provider != "stripe" || len(saved.Envelopes) != 1 {
		t.Fatalf("unexpected saved Trace: %#v", saved)
	}
	if !bytes.Equal(saved.Envelopes[0].Request.RawBodyBase64, payload) || saved.Envelopes[0].Request.BodyFidelity != "exact" {
		t.Fatalf("saved Trace lost exact request body: %#v", saved.Envelopes[0].Request)
	}
	if saved.Envelopes[0].Response == nil || saved.Envelopes[0].Response.Status != http.StatusNoContent {
		t.Fatalf("saved Trace lost application response: %#v", saved.Envelopes[0].Response)
	}
	info, err := os.Stat(savedPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("saved Trace permissions = %o, want 600", info.Mode().Perm())
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("listen command stopped with %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listen command did not stop after context cancellation")
	}

	if strings.Contains(stderr.String(), "evaluate live trace") || strings.Contains(stderr.String(), "forward failed") {
		t.Fatalf("unexpected live errors:\n%s", stderr.String())
	}
}

func TestListenCommandRejectsUnsafeOrIncompleteInvocation(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		contains string
	}{
		{
			name:     "missing forward target",
			args:     []string{"--provider", "stripe"},
			contains: "--forward-to is required",
		},
		{
			name:     "remote forward without opt in",
			args:     []string{"--provider", "stripe", "--forward-to", "https://example.com/webhook"},
			contains: "remote forwarding requires explicit opt-in",
		},
		{
			name:     "public listen without opt in",
			args:     []string{"--provider", "stripe", "--forward-to", "http://127.0.0.1:3000/webhook", "--addr", "0.0.0.0:4545"},
			contains: "public listening",
		},
		{
			name:     "provider and external pack",
			args:     []string{"--provider", "stripe", "--pack", stripePackPath(t), "--forward-to", "http://127.0.0.1:3000/webhook"},
			contains: "mutually exclusive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runListenContext(context.Background(), tc.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
			if !strings.Contains(stderr.String(), tc.contains) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tc.contains)
			}
		})
	}
}

func TestSaveTraceAtomicRejectsUnsafeTraceID(t *testing.T) {
	_, err := saveTraceAtomic(t.TempDir(), model.Trace{TraceID: "../../secret"})
	if err == nil || !strings.Contains(err.Error(), "unsafe trace id") {
		t.Fatalf("expected unsafe trace id rejection, got %v", err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, message func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message())
}

func TestNormalizeListenArgsSupportsHumanSyntax(t *testing.T) {
	got := normalizeListenArgs([]string{"mercadopago-webhooks", "http://127.0.0.1:8000/api/v1/payment-webhooks/connections/mercadopago/1/2", "--save-dir", ".wirelint/traces"})
	want := []string{"--provider", "mercadopago-webhooks", "--forward-to", "http://127.0.0.1:8000/api/v1/payment-webhooks/connections/mercadopago/1/2", "--save-dir", ".wirelint/traces"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("unexpected normalized args: got=%v want=%v", got, want)
	}
}

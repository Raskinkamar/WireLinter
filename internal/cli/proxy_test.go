package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Raskinkamar/WireLinter/internal/model"
)

type proxyTestBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *proxyTestBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *proxyTestBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestProxyCommandRunsGitHubGraphQLExchangeThroughEngine(t *testing.T) {
	payload := []byte(`{"query":"query Viewer { viewer { login } }","operationName":"Viewer","variables":{}}`)
	upstreamRequests := make(chan struct {
		body          []byte
		authorization string
	}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
			return
		}
		upstreamRequests <- struct {
			body          []byte
			authorization string
		}{append([]byte{}, body...), r.Header.Get("Authorization")}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Remaining", "4999")
		_, _ = w.Write([]byte(`{"data":{"viewer":{"login":"octocat"}}}`))
	}))
	defer upstream.Close()

	saveDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := &proxyTestBuffer{}
	stderr := &proxyTestBuffer{}
	ready := make(chan net.Addr, 1)
	done := make(chan int, 1)
	go func() {
		done <- runProxyContextWithReady(ctx, []string{
			"--provider", "github-graphql-api",
			"--target", upstream.URL,
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
		t.Fatalf("proxy did not become ready\nstdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}

	request, err := http.NewRequest(http.MethodPost, "http://"+address.String()+"/graphql", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer github-secret-token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("proxy response status = %d, want 200", response.StatusCode)
	}

	select {
	case observed := <-upstreamRequests:
		if !bytes.Equal(observed.body, payload) {
			t.Fatalf("upstream body changed: got %q want %q", observed.body, payload)
		}
		if observed.authorization != "Bearer github-secret-token" {
			t.Fatalf("upstream authorization changed: %q", observed.authorization)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not receive request")
	}

	waitForProxyTest(t, 5*time.Second, func() bool {
		return strings.Contains(stdout.String(), "PASS WL-GH-GQL-ERRORS-001")
	}, func() string {
		return "GraphQL semantic result was not emitted\nstdout:\n" + stdout.String() + "\nstderr:\n" + stderr.String()
	})

	var savedPath string
	waitForProxyTest(t, 5*time.Second, func() bool {
		matches, err := filepath.Glob(filepath.Join(saveDir, "trace_*.json"))
		if err != nil || len(matches) != 1 {
			return false
		}
		savedPath = matches[0]
		return true
	}, func() string { return "outbound canonical Trace was not saved" })

	raw, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved model.Trace
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("saved trace is invalid JSON: %v", err)
	}
	if len(saved.Envelopes) != 1 || saved.Envelopes[0].Direction != "outbound" {
		t.Fatalf("saved trace lost outbound direction: %#v", saved)
	}
	for _, header := range saved.Envelopes[0].Request.Headers {
		if strings.EqualFold(header.Name, "Authorization") {
			if !header.Redacted || header.Value != "Bearer <redacted>" {
				t.Fatalf("saved Authorization was not safely redacted: %#v", header)
			}
			if strings.Contains(header.Value, "github-secret-token") {
				t.Fatal("saved Authorization leaked credential")
			}
		}
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("proxy command stopped with %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy command did not stop after context cancellation")
	}
}

func TestProxyCommandRejectsUnsafeOrIncompleteInvocation(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		contains string
	}{
		{name: "missing target", args: []string{"--provider", "github-graphql-api"}, contains: "--target is required"},
		{name: "public listen without opt in", args: []string{"--provider", "github-graphql-api", "--target", "https://api.github.com", "--addr", "0.0.0.0:4546"}, contains: "public listening"},
		{name: "provider and external pack", args: []string{"--provider", "github-graphql-api", "--pack", "./pack", "--target", "https://api.github.com"}, contains: "mutually exclusive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runProxyContext(context.Background(), tc.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
			if !strings.Contains(stderr.String(), tc.contains) {
				t.Fatalf("stderr = %q, want substring %q", stderr.String(), tc.contains)
			}
		})
	}
}

func waitForProxyTest(t *testing.T, timeout time.Duration, condition func() bool, message func() string) {
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

func TestNormalizeProxyArgsSupportsHumanSyntax(t *testing.T) {
	got := normalizeProxyArgs([]string{"github-graphql-api", "https://api.github.com", "--save-dir", ".wirelint/traces"})
	want := []string{"--provider", "github-graphql-api", "--target", "https://api.github.com", "--save-dir", ".wirelint/traces"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("unexpected normalized args: got=%v want=%v", got, want)
	}
}

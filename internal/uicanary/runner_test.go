package uicanary

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/superserve-ai/canaries/internal/config"
	"github.com/superserve-ai/canaries/internal/lock"
	"github.com/superserve-ai/canaries/internal/metrics"
	"github.com/superserve-ai/canaries/internal/sandboxmetadata"
)

func TestExtractSandboxIDFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://console.superserve.ai/sandboxes/sb-12345/terminal/", "sb-12345"},
		{"https://console.superserve.ai/sandboxes/sb-abcdef?tab=settings", "sb-abcdef"},
		{"https://console.superserve.ai/sandboxes/sb-999/", "sb-999"},
		{"http://localhost:3000/sandboxes/sb-local", "sb-local"},
	}

	for _, tt := range tests {
		got := extractSandboxIDFromURL(tt.url)
		if got != tt.want {
			t.Errorf("extractSandboxIDFromURL(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

type mockServerState struct {
	sync.Mutex
	receivedBypassHeader       string
	receivedBypassCookieHeader string
	deletedSandbox             bool
	failTerminal               bool
}

func setupMockConsoleServer(opts ...*mockServerState) *httptest.Server {
	var state *mockServerState
	if len(opts) > 0 {
		state = opts[0]
	}

	mux := http.NewServeMux()
	var stateStatus = "Active"

	mux.HandleFunc("/auth/signin", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			email := r.FormValue("email")
			password := r.FormValue("password")
			if email == "" || password == "" {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, `<!DOCTYPE html><html><body><p role="alert" class="text-destructive">Invalid credentials</p></body></html>`)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name:  "sb-auth-token.0",
				Value: "valid-session",
				Path:  "/",
			})
			http.Redirect(w, r, "/sandboxes/", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Sign In</title></head>
<body>
  <h1>Sign In</h1>
  <form method="POST" action="/auth/signin">
    <input type="email" placeholder="Email" name="email" value="" />
    <input type="password" placeholder="Password" name="password" value="" />
    <button type="submit">Sign In</button>
  </form>
</body>
</html>`)
	})

	mux.HandleFunc("/sandboxes/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("deleted") == "true" {
			if state != nil {
				state.Lock()
				state.deletedSandbox = true
				state.Unlock()
			}
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Sandboxes</title></head>
<body>
  <h1>Sandboxes</h1>
  <button id="create-btn" onclick="document.getElementById('dialog').style.display='block'">Create sandbox</button>

  <div id="dialog" role="dialog" style="display:none;">
    <input type="text" placeholder="my-sandbox" id="name-input" />
    <button id="submit-create" onclick="document.getElementById('dialog').style.display='none'; document.getElementById('connect-dialog').style.display='block';">Create Sandbox</button>
  </div>

  <div id="connect-dialog" role="dialog" style="display:none;">
    <h3>Connect to Sandbox</h3>
    <pre>const sandbox = await Sandbox.connect("sb-mock-123", {
  apiKey: process.env.SUPERSERVE_API_KEY,
});</pre>
    <button onclick="window.location.href='/sandboxes/sb-mock-123/terminal/'">Open Terminal</button>
    <button onclick="document.getElementById('connect-dialog').style.display='none'">Done</button>
  </div>
</body>
</html>`)
	})

	mux.HandleFunc("/sandboxes/sb-mock-123/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Sandbox Detail</title></head>
<body>
  <section id="hero">
    <h1>ui-canary-test</h1>
    <span id="status-badge">%s</span>
  </section>

  <button id="stop-btn" onclick="document.getElementById('status-badge').innerText='Paused'">Stop</button>
  <button id="start-btn" onclick="document.getElementById('status-badge').innerText='Active'">Start</button>

  <button aria-label="More actions" onclick="document.getElementById('menu').style.display='block'">More actions</button>
  <div id="menu" style="display:none;">
    <div role="menuitem" onclick="document.getElementById('delete-dialog').style.display='block'">Delete sandbox</div>
  </div>

  <div id="delete-dialog" role="dialog" style="display:none;">
    <input placeholder="ui-canary-mock" id="delete-input" />
    <button id="confirm-del" onclick="window.location.href='/sandboxes/?deleted=true'">Delete</button>
  </div>
</body>
</html>`, stateStatus)
	})

	mux.HandleFunc("/sandboxes/sb-mock-123/terminal/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		shouldFail := false
		if state != nil {
			state.Lock()
			shouldFail = state.failTerminal
			state.Unlock()
		}

		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Terminal</title></head>
<body>
  <div class="header">
    <span id="status-badge">Active</span>
    <a href="/sandboxes/sb-mock-123/">ui-canary-test</a>
  </div>
  <div class="xterm" style="position:relative; width:100vw; height:100vh;" onclick="document.querySelector('.xterm-helper-textarea').focus()">
    <textarea class="xterm-helper-textarea" style="opacity:0; position:absolute; top:0; left:0;"></textarea>
    <div class="xterm-rows">
      <div id="term-line">root@sandbox-mock:~# </div>
    </div>
  </div>
  <script>
    var ta = document.querySelector('.xterm-helper-textarea');
    ta.addEventListener('input', function(e) {
      document.getElementById('term-line').innerText = 'root@sandbox-mock:~# ' + e.target.value;
    });
    window.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') {
        var lines = document.querySelector('.xterm-rows');
        var div = document.createElement('div');
        var val = ta.value;
        var match = val.match(/\$\(\(\s*(\d+)\s*\+\s*(\d+)\s*\)\)/);
        if (match) {
          if (%t) {
            div.innerText = 'terminal_error';
          } else {
            var sum = parseInt(match[1], 10) + parseInt(match[2], 10);
            div.innerText = 'RES_UI_' + sum;
          }
        } else {
          div.innerText = val;
        }
        lines.appendChild(div);
      }
    });
  </script>
</body>
</html>`, shouldFail)
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if state != nil {
			state.Lock()
			if v := r.Header.Get("x-vercel-protection-bypass"); v != "" {
				state.receivedBypassHeader = v
			}
			if v := r.Header.Get("x-vercel-set-bypass-cookie"); v != "" {
				state.receivedBypassCookieHeader = v
			}
			state.Unlock()
		}
		mux.ServeHTTP(w, r)
	})

	return httptest.NewServer(handler)
}

func skipIfPlaywrightUnavailable(t *testing.T) {
	t.Helper()
	pw, err := playwright.Run()
	if err != nil {
		t.Skipf("skipping browser test: playwright driver unavailable: %v", err)
		return
	}
	defer pw.Stop()
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{Headless: playwright.Bool(true)})
	if err != nil {
		t.Skipf("skipping browser test: chromium browser unavailable: %v", err)
		return
	}
	_ = browser.Close()
}

func newMockRunnerConfig(serverURL, bypassToken string) Config {
	return Config{
		BaseConfig: config.Config{
			Environment: "staging",
			Region:      "us-central1",
			Target:      "staging-us-central1",
			RunTimeout:  30 * time.Second,
		},
		ConsoleURL:             serverURL,
		Email:                  "canary@superserve.ai",
		Password:               "password123",
		VercelProtectionBypass: bypassToken,
		Headless:               true,
		StepTimeout:            5 * time.Second,
		TerminalTimeout:        5 * time.Second,
	}
}

func TestUIRunnerWithMockServer(t *testing.T) {
	skipIfPlaywrightUnavailable(t)

	state := &mockServerState{}
	server := setupMockConsoleServer(state)
	defer server.Close()

	artifactsDir, err := os.MkdirTemp("", "ui-canary-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(artifactsDir)

	cfg := newMockRunnerConfig(server.URL, "test-bypass-secret-123")
	cfg.ArtifactsDir = artifactsDir

	var taggedSandboxID string
	var taggedMetadata map[string]string
	mockTagger := &mockSandboxTagger{
		tagFn: func(ctx context.Context, sandboxID string, metadata map[string]string) error {
			taggedSandboxID = sandboxID
			taggedMetadata = metadata
			return nil
		},
	}

	runner := Runner{
		Config:  cfg,
		Locker:  lock.NoopLock{},
		Metrics: metrics.NoopProvider{},
		Clock:   time.Now,
		Tagger:  mockTagger,
	}

	// This integration test runs if playwright browser is available
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	err = runner.Run(ctx)
	if err != nil {
		t.Fatalf("Runner failed with email/password auth: %v", err)
	}

	if taggedSandboxID != "sb-mock-123" {
		t.Errorf("expected taggedSandboxID 'sb-mock-123', got %q", taggedSandboxID)
	}
	if taggedMetadata[sandboxmetadata.KeyManagedBy] != sandboxmetadata.ManagedByCanaryLegacy {
		t.Errorf("expected managed_by %q, got %q", sandboxmetadata.ManagedByCanaryLegacy, taggedMetadata[sandboxmetadata.KeyManagedBy])
	}

	state.Lock()
	defer state.Unlock()
	if state.receivedBypassHeader != "test-bypass-secret-123" {
		t.Errorf("expected bypass header 'test-bypass-secret-123', got %q", state.receivedBypassHeader)
	}
	if state.receivedBypassCookieHeader != "true" {
		t.Errorf("expected bypass cookie header 'true', got %q", state.receivedBypassCookieHeader)
	}
	if !state.deletedSandbox {
		t.Errorf("expected sandbox to be deleted in UI lifecycle")
	}
}

type mockSandboxTagger struct {
	tagFn func(ctx context.Context, sandboxID string, metadata map[string]string) error
}

func (m *mockSandboxTagger) TagSandbox(ctx context.Context, sandboxID string, metadata map[string]string) error {
	if m.tagFn != nil {
		return m.tagFn(ctx, sandboxID, metadata)
	}
	return nil
}

func TestUIRunnerWithoutBypassHeaders(t *testing.T) {
	skipIfPlaywrightUnavailable(t)

	state := &mockServerState{}
	server := setupMockConsoleServer(state)
	defer server.Close()

	cfg := newMockRunnerConfig(server.URL, "") // unconfigured bypass

	runner := Runner{
		Config:  cfg,
		Locker:  lock.NoopLock{},
		Metrics: metrics.NoopProvider{},
		Clock:   time.Now,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("Runner failed: %v", err)
	}

	state.Lock()
	defer state.Unlock()
	if state.receivedBypassHeader != "" {
		t.Errorf("expected no bypass header, got %q", state.receivedBypassHeader)
	}
	if state.receivedBypassCookieHeader != "" {
		t.Errorf("expected no bypass cookie header, got %q", state.receivedBypassCookieHeader)
	}
}

func TestDeferredCleanupOnPostCreateFailure(t *testing.T) {
	skipIfPlaywrightUnavailable(t)

	state := &mockServerState{failTerminal: true}
	server := setupMockConsoleServer(state)
	defer server.Close()

	cfg := newMockRunnerConfig(server.URL, "")
	cfg.StepTimeout = 3 * time.Second
	cfg.TerminalTimeout = 1 * time.Second

	runner := Runner{
		Config:  cfg,
		Locker:  lock.NoopLock{},
		Metrics: metrics.NoopProvider{},
		Clock:   time.Now,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := runner.Run(ctx)
	if err == nil {
		t.Fatal("expected runner to fail on terminal step")
	}

	state.Lock()
	defer state.Unlock()
	if !state.deletedSandbox {
		t.Errorf("expected deferred cleanup to delete sandbox when terminal step failed")
	}
}

func TestAuthenticateInvalidCredentials(t *testing.T) {
	skipIfPlaywrightUnavailable(t)

	server := setupMockConsoleServer()
	defer server.Close()

	cfg := newMockRunnerConfig(server.URL, "")
	cfg.Email = "" // invalid empty credentials
	cfg.Password = ""
	cfg.StepTimeout = 3 * time.Second
	cfg.TerminalTimeout = 3 * time.Second

	runner := Runner{
		Config:  cfg,
		Locker:  lock.NoopLock{},
		Metrics: metrics.NoopProvider{},
		Clock:   time.Now,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := runner.Run(ctx)
	if err == nil {
		t.Fatal("expected runner to fail with invalid credentials")
	}
}

func TestGenerateTerminalCommand(t *testing.T) {
	for i := 0; i < 20; i++ {
		cmd, expected := generateTerminalCommand()

		// Verify command structure: echo "RES_UI_$((nonceA + nonceB))"
		if !strings.HasPrefix(cmd, `echo "RES_UI_$((`) || !strings.HasSuffix(cmd, `))"`) {
			t.Fatalf("unexpected command format: %q", cmd)
		}

		// Verify expected output format: RES_UI_<sum>
		if !strings.HasPrefix(expected, "RES_UI_") {
			t.Fatalf("unexpected expectedOutput format: %q", expected)
		}

		// Extract nonces
		var a, b int
		n, err := fmt.Sscanf(cmd, `echo "RES_UI_$((%d + %d))"`, &a, &b)
		if err != nil || n != 2 {
			t.Fatalf("failed to parse nonces from command %q: %v", cmd, err)
		}

		if a < 1000 || a >= 10000 || b < 1000 || b >= 10000 {
			t.Errorf("nonces out of range [1000, 9999]: a=%d, b=%d", a, b)
		}
		if a == b {
			t.Errorf("expected distinct nonces, got a=%d == b=%d", a, b)
		}

		wantExpected := fmt.Sprintf("RES_UI_%d", a+b)
		if expected != wantExpected {
			t.Errorf("expectedOutput = %q, want %q", expected, wantExpected)
		}
	}
}

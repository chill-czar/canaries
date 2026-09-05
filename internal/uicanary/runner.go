package uicanary

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/playwright-community/playwright-go"
	"github.com/rs/zerolog/log"

	"github.com/superserve-ai/canaries/internal/lock"
	"github.com/superserve-ai/canaries/internal/metrics"
	"github.com/superserve-ai/canaries/internal/sandboxmetadata"
)

// SandboxTagger is an optional dependency for tagging sandbox ownership metadata
// via the API immediately after the sandbox ID is recovered from the browser URL.
// This ensures the janitor can discover and reap sandboxes that leak if a run
// crashes before reaching the delete step.
type SandboxTagger interface {
	TagSandbox(ctx context.Context, sandboxID string, metadata map[string]string) error
}

type Runner struct {
	Config  Config
	Locker  lock.Lock
	Metrics metrics.Provider
	Clock   func() time.Time
	Tagger  SandboxTagger // optional; if nil, metadata tagging is skipped
}

type RunResult struct {
	Err        error
	FailedStep string
	SandboxID  string
}

func (r Runner) now() time.Time {
	if r.Clock != nil {
		return r.Clock()
	}
	return time.Now()
}

func (r Runner) metricsProvider() metrics.Provider {
	if r.Metrics != nil {
		return r.Metrics
	}
	return metrics.NoopProvider{}
}

func (r Runner) Run(ctx context.Context) error {
	runTimeout := r.Config.BaseConfig.RunTimeout
	if runTimeout <= 0 {
		runTimeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	target := r.Config.BaseConfig.Target
	if target == "" {
		target = "staging-us-central1"
	}
	env := r.Config.BaseConfig.Environment
	region := r.Config.BaseConfig.Region
	if env == "" || region == "" {
		parts := strings.Split(target, "-")
		if len(parts) >= 2 {
			env = parts[0]
			region = strings.Join(parts[1:], "-")
		}
	}

	lockTTL := r.Config.BaseConfig.LockTTL
	if lockTTL <= 0 {
		lockTTL = 10 * time.Minute
	}

	if r.Locker != nil {
		outcome, lease, err := r.Locker.Acquire(ctx, target, lockTTL)
		if err != nil {
			return fmt.Errorf("acquire lock: %w", err)
		}
		if outcome == lock.OutcomeAlreadyRunning {
			r.metricsProvider().RecordOverlapSkip(ctx, env, region, target)
			log.Info().Str("target", target).Msg("UI canary skipped because another run holds the target lock")
			return nil
		}
		if lease != nil {
			defer func() {
				if relErr := lease.Release(context.Background()); relErr != nil {
					log.Warn().Err(relErr).Msg("failed to release lock lease")
				}
			}()
		}
	}

	scenario := "ui-lifecycle"

	r.metricsProvider().RecordExecutionDelta(ctx, env, region, target, scenario, 1)
	defer r.metricsProvider().RecordExecutionDelta(ctx, env, region, target, scenario, -1)

	runID := fmt.Sprintf("ui-%d-%s", r.now().Unix(), uuid.NewString()[:8])
	start := r.now()
	result := "failure"

	log.Info().
		Str("run_id", runID).
		Str("target", target).
		Str("console_url", r.Config.ConsoleURL).
		Str("scenario", scenario).
		Msg("UI lifecycle canary started")

	res := r.runLifecycle(ctx, runID)
	err := res.Err
	if err == nil {
		result = "success"
	}
	duration := r.now().Sub(start)
	r.metricsProvider().RecordRun(ctx, env, region, target, scenario, result, duration)

	if err != nil {
		log.Error().
			Err(err).
			Str("run_id", runID).
			Str("failed_step", res.FailedStep).
			Str("sandbox_id", res.SandboxID).
			Dur("duration", duration).
			Msg("UI lifecycle canary failed")
		return err
	}

	log.Info().
		Str("run_id", runID).
		Str("sandbox_id", res.SandboxID).
		Dur("duration", duration).
		Msg("UI lifecycle canary completed successfully")
	return nil
}

func (r Runner) runLifecycle(ctx context.Context, runID string) (res RunResult) {
	mp := r.metricsProvider()
	target := r.Config.BaseConfig.Target
	if target == "" {
		target = "staging-us-central1"
	}
	env := r.Config.BaseConfig.Environment
	region := r.Config.BaseConfig.Region
	if env == "" && target != "" {
		parts := strings.Split(target, "-")
		if len(parts) >= 2 {
			env = parts[0]
			region = strings.Join(parts[1:], "-")
		}
	}
	scenario := "ui-lifecycle"

	_ = playwright.Install(&playwright.RunOptions{
		SkipInstallBrowsers: true,
	})
	pw, err := playwright.Run()
	if err != nil {
		res.Err = fmt.Errorf("initialize playwright: %w", err)
		res.FailedStep = "driver_init"
		return res
	}
	defer func() {
		if stopErr := pw.Stop(); stopErr != nil {
			log.Warn().Err(stopErr).Msg("playwright stop error")
		}
	}()

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(r.Config.Headless),
	})
	if err != nil {
		res.Err = fmt.Errorf("launch chromium: %w", err)
		res.FailedStep = "browser_launch"
		return res
	}
	defer browser.Close()

	contextOpts := playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{Width: 1280, Height: 800},
	}
	if r.Config.VercelProtectionBypass != "" {
		contextOpts.ExtraHttpHeaders = map[string]string{
			"x-vercel-protection-bypass": r.Config.VercelProtectionBypass,
			"x-vercel-set-bypass-cookie": "true",
		}
	}

	bCtx, err := browser.NewContext(contextOpts)
	if err != nil {
		res.Err = fmt.Errorf("create browser context: %w", err)
		res.FailedStep = "browser_context"
		return res
	}
	defer bCtx.Close()

	page, err := bCtx.NewPage()
	if err != nil {
		res.Err = fmt.Errorf("create page: %w", err)
		res.FailedStep = "page_init"
		return res
	}
	defer page.Close()

	// Diagnostic artifact capture helper
	captureArtifacts := func(stepName string) {
		if r.Config.ArtifactsDir == "" {
			return
		}
		_ = os.MkdirAll(r.Config.ArtifactsDir, 0755)
		screenshotPath := filepath.Join(r.Config.ArtifactsDir, fmt.Sprintf("failure-%s-%s.png", stepName, runID))
		_, _ = page.Screenshot(playwright.PageScreenshotOptions{
			Path:     playwright.String(screenshotPath),
			FullPage: playwright.Bool(true),
		})
		log.Info().Str("screenshot", screenshotPath).Msg("captured failure screenshot")
	}

	stepTimeout := r.Config.StepTimeout
	stepTimeoutMs := float64(stepTimeout.Milliseconds())

	var (
		createdSandboxID   string
		createdSandboxName string
		sandboxDeleted     bool
	)

	// Guaranteed deferred cleanup if sandbox was created but not successfully deleted
	defer func() {
		if createdSandboxID != "" && !sandboxDeleted {
			log.Info().Str("sandbox_id", createdSandboxID).Str("sandbox_name", createdSandboxName).Msg("executing deferred sandbox cleanup on failure/exit")
			_ = r.deleteSandboxInUI(page, createdSandboxID, createdSandboxName, stepTimeoutMs)
		}
	}()

	// Step 1: Authenticate
	authStart := r.now()
	log.Info().Msg("UI step: authenticate")
	if err := Authenticate(ctx, page, r.Config); err != nil {
		mp.RecordStep(ctx, env, region, target, scenario, "authenticate", "failure", r.now().Sub(authStart))
		captureArtifacts("authenticate")
		res.Err = fmt.Errorf("authenticate: %w", err)
		res.FailedStep = "authenticate"
		return res
	}
	mp.RecordStep(ctx, env, region, target, scenario, "authenticate", "success", r.now().Sub(authStart))

	// Step 2: Create Sandbox
	createStart := r.now()
	log.Info().Msg("UI step: create_sandbox")
	sandboxName := fmt.Sprintf("ui-canary-%d", r.now().Unix())
	createdSandboxName = sandboxName
	sbID, err := r.createSandboxInUI(page, sandboxName, stepTimeoutMs, func(id string) {
		createdSandboxID = id
		res.SandboxID = id
	})
	if err != nil {
		mp.RecordStep(ctx, env, region, target, scenario, "create_sandbox", "failure", r.now().Sub(createStart))
		captureArtifacts("create_sandbox")
		res.Err = fmt.Errorf("create sandbox: %w", err)
		res.FailedStep = "create_sandbox"
		return res
	}
	createdSandboxID = sbID
	res.SandboxID = createdSandboxID

	// Tag the sandbox with ownership metadata so the janitor can reap it if this
	// run crashes before the delete step. Best-effort: a tagging failure is logged
	// but does not fail the canary run.
	if r.Tagger != nil {
		tagMeta := sandboxmetadata.LegacyCanaryMetadata(
			env, region, target, runID,
			r.now(),
			r.now().Add(r.Config.BaseConfig.RetainFailedSandboxTTL),
		)
		if tagErr := r.Tagger.TagSandbox(ctx, createdSandboxID, tagMeta); tagErr != nil {
			log.Warn().Err(tagErr).Str("sandbox_id", createdSandboxID).Msg("failed to tag sandbox metadata; janitor cannot reap it if run fails")
		} else {
			log.Debug().Str("sandbox_id", createdSandboxID).Msg("sandbox tagged with canary ownership metadata")
		}
	}

	mp.RecordStep(ctx, env, region, target, scenario, "create_sandbox", "success", r.now().Sub(createStart))

	// Step 3: Interactive Terminal Execution
	termStart := r.now()
	log.Info().Msg("UI step: terminal_exec")
	if err := r.executeTerminalCommand(page, res.SandboxID, r.Config.TerminalTimeout); err != nil {
		mp.RecordStep(ctx, env, region, target, scenario, "terminal_exec", "failure", r.now().Sub(termStart))
		captureArtifacts("terminal_exec")
		res.Err = fmt.Errorf("terminal execution: %w", err)
		res.FailedStep = "terminal_exec"
		return res
	}
	mp.RecordStep(ctx, env, region, target, scenario, "terminal_exec", "success", r.now().Sub(termStart))

	// Step 4: Pause Sandbox
	pauseStart := r.now()
	log.Info().Msg("UI step: pause_sandbox")
	if err := r.pauseSandboxInUI(page, res.SandboxID, stepTimeoutMs); err != nil {
		mp.RecordStep(ctx, env, region, target, scenario, "pause_sandbox", "failure", r.now().Sub(pauseStart))
		captureArtifacts("pause_sandbox")
		res.Err = fmt.Errorf("pause sandbox: %w", err)
		res.FailedStep = "pause_sandbox"
		return res
	}
	mp.RecordStep(ctx, env, region, target, scenario, "pause_sandbox", "success", r.now().Sub(pauseStart))

	// Step 5: Resume Sandbox
	resumeStart := r.now()
	log.Info().Msg("UI step: resume_sandbox")
	if err := r.resumeSandboxInUI(page, res.SandboxID, stepTimeoutMs); err != nil {
		mp.RecordStep(ctx, env, region, target, scenario, "resume_sandbox", "failure", r.now().Sub(resumeStart))
		captureArtifacts("resume_sandbox")
		res.Err = fmt.Errorf("resume sandbox: %w", err)
		res.FailedStep = "resume_sandbox"
		return res
	}
	mp.RecordStep(ctx, env, region, target, scenario, "resume_sandbox", "success", r.now().Sub(resumeStart))

	// Step 6: Delete Sandbox
	deleteStart := r.now()
	log.Info().Msg("UI step: delete_sandbox")
	if err := r.deleteSandboxInUI(page, res.SandboxID, sandboxName, stepTimeoutMs); err != nil {
		mp.RecordStep(ctx, env, region, target, scenario, "delete_sandbox", "failure", r.now().Sub(deleteStart))
		captureArtifacts("delete_sandbox")
		res.Err = fmt.Errorf("delete sandbox: %w", err)
		res.FailedStep = "delete_sandbox"
		return res
	}
	sandboxDeleted = true
	mp.RecordStep(ctx, env, region, target, scenario, "delete_sandbox", "success", r.now().Sub(deleteStart))

	return res
}

func (r Runner) createSandboxInUI(page playwright.Page, sandboxName string, timeoutMs float64, onIDDiscovered func(string)) (string, error) {
	// Navigate to sandboxes list if not already there
	if !strings.Contains(page.URL(), "/sandboxes") {
		listURL := r.Config.ConsoleURL + "/sandboxes/"
		log.Info().Str("url", listURL).Msg("navigating to sandboxes list")
		if _, err := page.Goto(listURL, playwright.PageGotoOptions{
			Timeout:   playwright.Float(timeoutMs),
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		}); err != nil {
			return "", fmt.Errorf("navigate to sandboxes: %w", err)
		}
	}

	// Trigger "Create sandbox" dialog
	log.Info().Msg("locating create sandbox trigger button")
	createBtn := page.Locator("button:has-text('Create sandbox'), button:has-text('Create Sandbox')").First()
	if err := createBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		return "", fmt.Errorf("waiting for create sandbox button: %w", err)
	}
	if err := createBtn.Click(); err != nil {
		return "", fmt.Errorf("click create sandbox button: %w", err)
	}

	// Fill Sandbox Name in dialog (scope to dialog to avoid background search bar)
	log.Info().Msg("waiting for create sandbox dialog name input")
	nameInput := page.Locator("input[placeholder='my-sandbox'], div[role='dialog'] input, .dialog-popup input, div[data-state='open'] input").First()
	if err := nameInput.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		return "", fmt.Errorf("waiting for sandbox name input: %w", err)
	}

	log.Info().Str("sandbox_name", sandboxName).Msg("filling sandbox name")
	_ = nameInput.Click()
	_ = nameInput.Fill("")
	_ = nameInput.Fill(sandboxName)

	// Wait for Create Sandbox submit button inside dialog
	submitDialogBtn := page.Locator("div[role='dialog'] button:has-text('Create Sandbox'), .dialog-popup button:has-text('Create Sandbox'), button:has-text('Create Sandbox')").Last()
	if err := submitDialogBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		return "", fmt.Errorf("waiting for submit button in create dialog: %w", err)
	}

	// Ensure button is enabled by re-typing if React synthetic event was delayed
	for i := 0; i < 15; i++ {
		disabled, err := submitDialogBtn.IsDisabled()
		if err == nil && !disabled {
			break
		}
		_ = nameInput.Click()
		_ = nameInput.Fill(sandboxName)
		time.Sleep(200 * time.Millisecond)
	}

	var (
		sandboxID string
		idMu      sync.Mutex
	)
	setID := func(id string) {
		idMu.Lock()
		defer idMu.Unlock()
		if sandboxID == "" && id != "" {
			sandboxID = id
			log.Info().Str("sandbox_id", sandboxID).Msg("discovered created sandbox ID")
			if onIDDiscovered != nil {
				onIDDiscovered(id)
			}
		}
	}

	// Intercept backend creation response to grab ID immediately on wire asynchronously.
	// NOTE: Must run inside a goroutine to avoid deadlocking the Playwright message reader.
	responseHandler := func(res playwright.Response) {
		go func(r playwright.Response) {
			u := r.URL()
			if strings.Contains(u, "/sandboxes") && r.Request().Method() == "POST" && r.Status() >= 200 && r.Status() < 300 {
				body, err := r.Body()
				if err == nil {
					var data struct {
						ID string `json:"id"`
					}
					if err := json.Unmarshal(body, &data); err == nil && data.ID != "" {
						setID(data.ID)
					}
				}
			}
		}(res)
	}
	page.On("response", responseHandler)
	defer page.RemoveListener("response", responseHandler)

	log.Info().Msg("submitting create sandbox dialog")
	if err := submitDialogBtn.Click(); err != nil {
		return "", fmt.Errorf("submit create sandbox dialog: %w", err)
	}
	log.Info().Msg("create sandbox submitted; awaiting connect dialog or navigation")

	// Locators for ConnectSandboxDialog actions
	openTerminalBtn := page.Locator("div[role='dialog'] button:has-text('Open Terminal'), .dialog-popup button:has-text('Open Terminal'), button:has-text('Open Terminal')").First()
	doneBtn := page.Locator("div[role='dialog'] button:has-text('Done'), .dialog-popup button:has-text('Done'), button:has-text('Done')").First()

	// Wait up to timeout for ConnectSandboxDialog, direct detail navigation, or table row appearance
	pollDeadline := r.now().Add(time.Duration(timeoutMs) * time.Millisecond)
	for r.now().Before(pollDeadline) {
		// 1. Check if ConnectSandboxDialog appeared with "Open Terminal"
		if count, _ := openTerminalBtn.Count(); count > 0 {
			if visible, _ := openTerminalBtn.IsVisible(); visible {
				if id := extractSandboxIDFromDialog(page); id != "" {
					setID(id)
				}
				_ = openTerminalBtn.Click()
				log.Info().Str("sandbox_id", sandboxID).Msg("clicked Open Terminal; waiting for navigation to terminal")
				_ = page.WaitForURL(fmt.Sprintf("%s/sandboxes/%s/**", r.Config.ConsoleURL, sandboxID), playwright.PageWaitForURLOptions{
					Timeout: playwright.Float(5000),
				})
				if id := extractSandboxIDFromURL(page.URL()); id != "" {
					setID(id)
					break
				}
			}
		}

		// 2. Check if URL already contains sandbox ID
		if id := extractSandboxIDFromURL(page.URL()); id != "" {
			setID(id)
			break
		}

		// 3. If Done button appeared without Open Terminal (fallback), inspect snippet then dismiss
		if count, _ := doneBtn.Count(); count > 0 {
			if visible, _ := doneBtn.IsVisible(); visible {
				if id := extractSandboxIDFromDialog(page); id != "" {
					setID(id)
				}
				_ = doneBtn.Click()
			}
		}

		// 4. If row matching our sandboxName is in the table, click it to navigate to detail
		row := page.Locator(fmt.Sprintf("tr:has-text('%s'), div[role='row']:has-text('%s')", sandboxName, sandboxName)).First()
		if count, _ := row.Count(); count > 0 {
			_ = row.Click()
			time.Sleep(500 * time.Millisecond)
			if id := extractSandboxIDFromURL(page.URL()); id != "" {
				setID(id)
				break
			}
		}

		if sandboxID != "" {
			break
		}

		time.Sleep(500 * time.Millisecond)
	}

	// 5. Fallback: navigate directly to sandboxes list and find row
	if sandboxID == "" {
		listURL := fmt.Sprintf("%s/sandboxes/", r.Config.ConsoleURL)
		_, _ = page.Goto(listURL, playwright.PageGotoOptions{
			Timeout:   playwright.Float(timeoutMs),
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		})
		time.Sleep(1 * time.Second)
		row := page.Locator(fmt.Sprintf("tr:has-text('%s'), div[role='row']:has-text('%s')", sandboxName, sandboxName)).First()
		if count, _ := row.Count(); count > 0 {
			_ = row.Click()
			time.Sleep(500 * time.Millisecond)
			if id := extractSandboxIDFromURL(page.URL()); id != "" {
				setID(id)
			}
		}
	}

	if sandboxID == "" {
		return "", fmt.Errorf("could not extract sandbox ID after creation")
	}

	// Navigate to sandbox detail page if not already on a sandbox page
	if !strings.HasPrefix(page.URL(), fmt.Sprintf("%s/sandboxes/%s", r.Config.ConsoleURL, sandboxID)) {
		detailURL := fmt.Sprintf("%s/sandboxes/%s/", r.Config.ConsoleURL, sandboxID)
		if _, err := page.Goto(detailURL, playwright.PageGotoOptions{
			Timeout:   playwright.Float(timeoutMs),
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		}); err != nil {
			return sandboxID, fmt.Errorf("navigate to detail page %s: %w", detailURL, err)
		}
	}

	// Wait for "Active" status indicator in SandboxStatusHero or Terminal header,
	// periodically dispatching window focus event to prompt React Query to refetch
	log.Info().Str("sandbox_id", sandboxID).Msg("waiting for sandbox to become active")
	activeDeadline := r.now().Add(time.Duration(timeoutMs) * time.Millisecond)
	for r.now().Before(activeDeadline) {
		activeBadge := page.Locator("section:has-text('Active'), span:has-text('Active'), td:has-text('Active'), div:has-text('Active')").First()
		if count, _ := activeBadge.Count(); count > 0 {
			if visible, _ := activeBadge.IsVisible(); visible {
				log.Info().Str("sandbox_id", sandboxID).Msg("sandbox is Active")
				return sandboxID, nil
			}
		}
		time.Sleep(1 * time.Second)
		_, _ = page.Evaluate("() => window.dispatchEvent(new Event('focus'))")
	}

	return sandboxID, fmt.Errorf("waiting for sandbox %s to become active timed out", sandboxID)
}

func (r Runner) executeTerminalCommand(page playwright.Page, sandboxID string, timeout time.Duration) error {
	timeoutMs := float64(timeout.Milliseconds())

	// Navigate to terminal page if not already there
	terminalURL := fmt.Sprintf("%s/sandboxes/%s/terminal/", r.Config.ConsoleURL, sandboxID)
	if !strings.Contains(page.URL(), "/terminal") {
		if _, err := page.Goto(terminalURL, playwright.PageGotoOptions{
			Timeout:   playwright.Float(timeoutMs),
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		}); err != nil {
			return fmt.Errorf("navigate to terminal: %w", err)
		}
	}

	// Wait for xterm container to be present
	xtermContainer := page.Locator(".xterm, .xterm-screen, .xterm-rows").First()
	if err := xtermContainer.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		return fmt.Errorf("waiting for terminal xterm container: %w", err)
	}

	// Helper to extract current terminal buffer or text
	extractTerminalText := func() string {
		evalResult, evalErr := page.Evaluate(`() => {
			// 1. Try React Fiber hooks (termRef / serializeRef)
			for (const node of document.querySelectorAll('*')) {
				const key = Object.keys(node).find(k => k.startsWith('__reactFiber') || k.startsWith('__reactInternalInstance'));
				if (!key) continue;
				let fiber = node[key];
				while (fiber) {
					let hook = fiber.memoizedState;
					while (hook) {
						if (hook.memoizedState && typeof hook.memoizedState === 'object') {
							const state = hook.memoizedState;
							if (state.current) {
								if (typeof state.current.serialize === 'function') {
									try { return state.current.serialize(); } catch (e) {}
								}
								if (state.current.buffer && state.current.buffer.active) {
									const buf = state.current.buffer.active;
									let lines = [];
									for (let i = 0; i < buf.length; i++) {
										const line = buf.getLine(i);
										if (line) lines.push(line.translateToString(true));
									}
									return lines.join('\n');
								}
							}
						}
						hook = hook.next;
					}
					fiber = fiber.return;
				}
			}

			// 2. Try DOM _xterm property
			for (const node of document.querySelectorAll('*')) {
				if (node._xterm && node._xterm.buffer && node._xterm.buffer.active) {
					const buf = node._xterm.buffer.active;
					let lines = [];
					for (let i = 0; i < buf.length; i++) {
						const line = buf.getLine(i);
						if (line) lines.push(line.translateToString(true));
					}
					return lines.join('\n');
				}
			}

			// 3. Fallback: DOM textContent
			const el = document.querySelector('.xterm-rows') || document.querySelector('.xterm-accessibility') || document.querySelector('.xterm') || document.body;
			return el ? (el.textContent || el.innerText || '') : '';
		}`)
		if evalErr == nil {
			if s, ok := evalResult.(string); ok {
				return s
			}
		}
		text, _ := page.Locator(".xterm-rows, .xterm, div.xterm-screen").First().TextContent()
		return text
	}

	// 1. Wait for terminal WebSocket to connect and prompt to be ready (recovering from any transient "connection lost")
	readyDeadline := r.now().Add(30 * time.Second)
	promptReady := false
	for r.now().Before(readyDeadline) {
		text := extractTerminalText()
		// If connected and has shell prompt
		if strings.Contains(text, "root@") || strings.Contains(text, "#") || strings.Contains(text, "$") {
			promptReady = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !promptReady {
		log.Warn().Str("sandbox_id", sandboxID).Msg("shell prompt did not appear within 30s, proceeding to attempt execution")
	}

	helperTextarea := page.Locator(".xterm-helper-textarea").First()

	// Focus the terminal by clicking its dynamic bounding box center and focusing helper textarea
	focusTerminal := func() {
		if box, err := xtermContainer.BoundingBox(); err == nil && box != nil {
			_ = page.Mouse().Click(box.X+box.Width/2, box.Y+box.Height/2)
		} else {
			_ = xtermContainer.Click()
		}
		_, _ = page.Evaluate("() => { const ta = document.querySelector('.xterm-helper-textarea'); if (ta) { ta.focus(); } }")
		if count, _ := helperTextarea.Count(); count > 0 {
			_ = helperTextarea.Focus()
		}
	}

	focusTerminal()
	time.Sleep(500 * time.Millisecond)

	// Generate arithmetic transformation operands so typed keystrokes cannot false-positive match the evaluated output
	cmd, expectedOutput := generateTerminalCommand()

	// Send echo command function
	sendCommand := func() error {
		focusTerminal()
		if err := page.Keyboard().Type(cmd, playwright.KeyboardTypeOptions{Delay: playwright.Float(30)}); err != nil {
			return fmt.Errorf("type command to terminal: %w", err)
		}
		time.Sleep(300 * time.Millisecond)
		if err := page.Keyboard().Press("Enter"); err != nil {
			return fmt.Errorf("press Enter in terminal: %w", err)
		}
		return nil
	}

	if err := sendCommand(); err != nil {
		return err
	}

	// Poll terminal until transformed output appears, retrying command once if needed
	pollDeadline := r.now().Add(timeout)
	lastRetry := r.now()
	for r.now().Before(pollDeadline) {
		text := extractTerminalText()
		if strings.Contains(text, expectedOutput) {
			log.Info().Str("expected_output", expectedOutput).Msg("terminal verification verified transformed shell output")
			return nil
		}

		// If 5 seconds passed without seeing the output, try typing once more (e.g. if a reconnect occurred)
		if r.now().Sub(lastRetry) > 5*time.Second {
			_ = sendCommand()
			lastRetry = r.now()
		}

		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("terminal output did not contain expected transformed sentinel %q within timeout", expectedOutput)
}

func (r Runner) pauseSandboxInUI(page playwright.Page, sandboxID string, timeoutMs float64) error {
	detailURL := fmt.Sprintf("%s/sandboxes/%s/", r.Config.ConsoleURL, sandboxID)
	if !strings.HasPrefix(page.URL(), fmt.Sprintf("%s/sandboxes/%s", r.Config.ConsoleURL, sandboxID)) || strings.Contains(page.URL(), "/terminal") {
		if _, err := page.Goto(detailURL, playwright.PageGotoOptions{
			Timeout:   playwright.Float(timeoutMs),
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		}); err != nil {
			return fmt.Errorf("navigate to sandbox detail: %w", err)
		}
	}

	// Click "Stop" button
	stopBtn := page.Locator("button:has-text('Stop')").First()
	if err := stopBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		return fmt.Errorf("waiting for Stop button: %w", err)
	}
	if err := stopBtn.Click(); err != nil {
		return fmt.Errorf("click Stop button: %w", err)
	}

	// Wait for status hero to report "Paused"
	pausedBadge := page.Locator("section:has-text('Paused'), span:has-text('Paused'), td:has-text('Paused')").First()
	if err := pausedBadge.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		return fmt.Errorf("waiting for Paused status: %w", err)
	}

	return nil
}

func (r Runner) resumeSandboxInUI(page playwright.Page, sandboxID string, timeoutMs float64) error {
	detailURL := fmt.Sprintf("%s/sandboxes/%s/", r.Config.ConsoleURL, sandboxID)
	if !strings.HasPrefix(page.URL(), fmt.Sprintf("%s/sandboxes/%s", r.Config.ConsoleURL, sandboxID)) || strings.Contains(page.URL(), "/terminal") {
		if _, err := page.Goto(detailURL, playwright.PageGotoOptions{
			Timeout:   playwright.Float(timeoutMs),
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		}); err != nil {
			return fmt.Errorf("navigate to sandbox detail for resume: %w", err)
		}
	}

	// Click "Start" button
	startBtn := page.Locator("button:has-text('Start')").First()
	if err := startBtn.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		return fmt.Errorf("waiting for Start button: %w", err)
	}
	if err := startBtn.Click(); err != nil {
		return fmt.Errorf("click Start button: %w", err)
	}

	// Wait for status hero to report "Active"
	activeBadge := page.Locator("section:has-text('Active'), span:has-text('Active'), td:has-text('Active')").First()
	if err := activeBadge.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		return fmt.Errorf("waiting for Active status after resume: %w", err)
	}

	return nil
}

func (r Runner) deleteSandboxInUI(page playwright.Page, sandboxID, sandboxName string, timeoutMs float64) error {
	detailURL := fmt.Sprintf("%s/sandboxes/%s/", r.Config.ConsoleURL, sandboxID)
	if !strings.HasPrefix(page.URL(), fmt.Sprintf("%s/sandboxes/%s", r.Config.ConsoleURL, sandboxID)) || strings.Contains(page.URL(), "/terminal") {
		if _, err := page.Goto(detailURL, playwright.PageGotoOptions{
			Timeout:   playwright.Float(timeoutMs),
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		}); err != nil {
			return fmt.Errorf("navigate to sandbox detail for deletion: %w", err)
		}
	}

	// Open More actions menu
	menuTrigger := page.Locator("button[aria-label='More actions']").First()
	if err := menuTrigger.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		// Fallback: look for direct Delete button
		directDeleteBtn := page.Locator("button:has-text('Delete')").First()
		if count, _ := directDeleteBtn.Count(); count > 0 {
			_ = directDeleteBtn.Click()
		} else {
			return fmt.Errorf("waiting for actions menu: %w", err)
		}
	} else {
		if err := menuTrigger.Click(); err != nil {
			return fmt.Errorf("click actions menu trigger: %w", err)
		}

		// Click "Delete sandbox" menu item
		deleteMenuItem := page.Locator("div[role='menuitem']:has-text('Delete sandbox'), button:has-text('Delete sandbox')").First()
		if err := deleteMenuItem.WaitFor(playwright.LocatorWaitForOptions{
			State:   playwright.WaitForSelectorStateVisible,
			Timeout: playwright.Float(timeoutMs),
		}); err != nil {
			return fmt.Errorf("waiting for Delete sandbox menu item: %w", err)
		}
		if err := deleteMenuItem.Click(); err != nil {
			return fmt.Errorf("click Delete sandbox menu item: %w", err)
		}
	}

	// Delete confirmation dialog: type expected sandbox name
	dialog := page.Locator("div[role='dialog'], [role='alertdialog'], .dialog-popup, #delete-dialog").First()
	if err := dialog.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		return fmt.Errorf("waiting for delete confirmation dialog: %w", err)
	}

	confirmInput := dialog.Locator("input").First()
	if err := confirmInput.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateVisible,
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		return fmt.Errorf("waiting for delete confirmation input: %w", err)
	}
	_ = confirmInput.Click()
	_ = confirmInput.Fill("")
	_ = confirmInput.PressSequentially(sandboxName, playwright.LocatorPressSequentiallyOptions{Delay: playwright.Float(30)})

	// Wait for the Delete button to become enabled and click it
	deleteBtn := dialog.Locator("button:has-text('Delete')").First()
	deadline := r.now().Add(time.Duration(timeoutMs) * time.Millisecond)
	clicked := false
	for r.now().Before(deadline) {
		disabled, err := deleteBtn.IsDisabled()
		if err == nil && !disabled {
			if err := deleteBtn.Click(); err == nil {
				clicked = true
				break
			}
		}
		// Fallback re-fill if React state didn't pick up typing
		_ = confirmInput.Fill(sandboxName)
		time.Sleep(300 * time.Millisecond)
	}

	if !clicked {
		return fmt.Errorf("confirm delete button remained disabled or could not be clicked")
	}

	// Wait for the delete dialog to close (indicates DELETE API call completed)
	_ = dialog.WaitFor(playwright.LocatorWaitForOptions{
		State:   playwright.WaitForSelectorStateHidden,
		Timeout: playwright.Float(timeoutMs),
	})

	// Wait for navigation away from the detail page back to the sandboxes dashboard
	listURL := fmt.Sprintf("%s/sandboxes/", r.Config.ConsoleURL)
	if err := page.WaitForURL(listURL+"**", playwright.PageWaitForURLOptions{
		Timeout: playwright.Float(timeoutMs),
	}); err != nil {
		_, _ = page.Goto(listURL, playwright.PageGotoOptions{
			Timeout:   playwright.Float(timeoutMs),
			WaitUntil: playwright.WaitUntilStateNetworkidle,
		})
	}

	// Poll until deleted sandbox is verified gone from the dashboard table
	time.Sleep(1 * time.Second)
	pollDeadline := r.now().Add(time.Duration(timeoutMs) * time.Millisecond)
	for r.now().Before(pollDeadline) {
		row := page.Locator(fmt.Sprintf("tr:has-text('%s'), div[role='row']:has-text('%s')", sandboxName, sandboxName)).First()
		count, _ := row.Count()
		if count == 0 {
			return nil
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("sandbox %s still present in table after deletion", sandboxName)
}

func extractSandboxIDFromURL(rawURL string) string {
	parts := strings.Split(rawURL, "/")
	for i, part := range parts {
		if part == "sandboxes" && i+1 < len(parts) {
			id := parts[i+1]
			// Trim query or trailing slash
			if idx := strings.IndexAny(id, "?#"); idx != -1 {
				id = id[:idx]
			}
			return strings.TrimSpace(id)
		}
	}
	return ""
}

var connectSandboxRegex = regexp.MustCompile(`Sandbox\.connect\(\s*["']([^"']+)["']`)

func extractSandboxIDFromDialog(page playwright.Page) string {
	dialogs := page.Locator("div[role='dialog'], .dialog-popup")
	count, _ := dialogs.Count()
	for i := 0; i < count; i++ {
		d := dialogs.Nth(i)
		if visible, _ := d.IsVisible(); visible {
			if text, err := d.TextContent(); err == nil {
				if match := connectSandboxRegex.FindStringSubmatch(text); len(match) > 1 {
					return match[1]
				}
			}
		}
	}
	return ""
}

const terminalSentinelPrefix = "RES_UI_"

func generateTerminalCommand() (command string, expectedOutput string) {
	randNonce := func() int { return 1000 + rand.Intn(9000) }
	nonceA := randNonce()
	nonceB := randNonce()
	for nonceB == nonceA {
		nonceB = randNonce()
	}
	command = fmt.Sprintf(`echo "%s$((%d + %d))"`, terminalSentinelPrefix, nonceA, nonceB)
	expectedOutput = fmt.Sprintf("%s%d", terminalSentinelPrefix, nonceA+nonceB)
	return command, expectedOutput
}

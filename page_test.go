package apxchallenge

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderPageInlinesAssetsAndValues(t *testing.T) {
	html := renderPage("TOKEN123", 17, "/__apx_challenge/verify")
	require.Contains(t, html, "TOKEN123")                // challenge token injected
	require.Contains(t, html, "17")                      // difficulty injected
	require.Contains(t, html, "/__apx_challenge/verify") // verify path injected
	require.Contains(t, html, "async function solve")    // pow.js inlined
	require.Contains(t, html, "<style>")                 // css inlined
	require.NotContains(t, html, "{{")                   // no unreplaced placeholders
	require.Contains(t, html, `method="POST"`)           // native form POST
	require.Contains(t, html, `action="/__apx_challenge/verify"`)
	require.Contains(t, html, `name="solution"`)
}

func TestRenderVerifyWidgetSubstitutes(t *testing.T) {
	out := renderVerifyWidget("/__apx_verify/challenge", "/__apx_verify/token")
	if strings.Contains(out, "{{CHALLENGE_PATH}}") || strings.Contains(out, "{{TOKEN_PATH}}") {
		t.Fatal("placeholders not substituted")
	}
	if !strings.Contains(out, "/__apx_verify/token") {
		t.Fatal("token path missing")
	}
	if !strings.Contains(out, "_apx_verify_token") {
		t.Fatal("hidden field name missing from widget")
	}
}

// TestRenderVerifyWidgetWireContract guards the browser-side literals that the
// Go endpoint/token code (Task 6) depends on but that Go tests can't execute.
// A future accidental deletion of any of these breaks interop silently.
func TestRenderVerifyWidgetWireContract(t *testing.T) {
	out := renderVerifyWidget("/__apx_verify/challenge", "/__apx_verify/token")
	require.Contains(t, out, "/__apx_verify/challenge") // challenge path substituted
	require.Contains(t, out, `'SHA-256'`)               // WebCrypto PoW digest algo
	require.Contains(t, out, "crypto.subtle")           // WebCrypto used
	require.Contains(t, out, `+ "." +`)                 // exact challenge + "." + solution construction
	// Probes JSON field names must byte-match the Go Probes struct tags.
	require.Contains(t, out, "fill_ms")
	require.Contains(t, out, "interactions")
	require.Contains(t, out, "webdriver")
	require.Contains(t, out, "missing_apis")
	// Token-request form field names read by r.FormValue in Task 6.
	require.Contains(t, out, "challenge")
	require.Contains(t, out, "solution")
	require.Contains(t, out, "probes")
	require.Contains(t, out, "X-Apx-Verify-Token") // header for JSON/fetch submitters
	require.Contains(t, out, "window.apxVerify")   // public API
}

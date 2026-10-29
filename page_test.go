package apxchallenge

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderPageInlinesAssetsAndValues(t *testing.T) {
	html := renderPage("TOKEN123", 17, "/__apx_challenge/verify", "/dashboard?a=1", 0)
	require.Contains(t, html, "TOKEN123")                // challenge token injected
	require.Contains(t, html, "17")                      // difficulty injected
	require.Contains(t, html, "/__apx_challenge/verify") // verify path injected
	require.Contains(t, html, "function powCore()")      // pow.js inlined
	require.Contains(t, html, "<style>")                 // css inlined
	require.NotContains(t, html, "{{")                   // no unreplaced placeholders
	require.Contains(t, html, `method="POST"`)           // native form POST
	require.Contains(t, html, `action="/__apx_challenge/verify"`)
	require.Contains(t, html, `name="solution"`)
	require.Contains(t, html, `name="ret" value="/dashboard?a=1"`)
}

func TestRenderPageTimeoutSubstituted(t *testing.T) {
	def := renderPage("T", 8, "/v", "/", 0)
	require.Contains(t, def, "var TIMEOUT_MS = 20000;") // default when unset
	require.NotContains(t, def, "{{TIMEOUT_MS}}")

	custom := renderPage("T", 8, "/v", "/", 4500)
	require.Contains(t, custom, "var TIMEOUT_MS = 4500;")
	require.NotContains(t, custom, "20000")
}

func TestRenderPageFailureUI(t *testing.T) {
	html := renderPage("T", 8, "/v", "/x", 0)
	require.Contains(t, html, "window.apxChallengeFail")
	require.Contains(t, html, "window.apxChallengeDone")
	require.Contains(t, html, "window.apxChallengeProgress")
	require.Contains(t, html, `id="apx-slow"`)
	require.Contains(t, html, "Still checking… this can take a minute on slower devices.")
	require.Contains(t, html, `id="apx-nocookies"`)
	// Show/hide must not depend on the reflected hidden property.
	require.Contains(t, html, `el.removeAttribute("hidden"); el.style.display = "block";`)
	require.NotContains(t, html, ".hidden = ")
	require.Contains(t, html, `id="apx-failed"`)
	require.Contains(t, html, `id="apx-fallback-slot"`)
	require.Contains(t, html, "This check didn't finish in your browser.")
	require.Contains(t, html, "location.reload()")
	require.Contains(t, html, `<noscript>`)
	require.Contains(t, html, `<a class="button" href="/x">`)
	// The failure-UI script must run before the inlined solver so the hooks
	// exist; locate the solver by its own inlined text, not its internals.
	solver := strings.Index(html, "<script>"+powJS+"</script>")
	require.NotEqual(t, -1, solver)
	require.Less(t, strings.Index(html, "window.apxChallengeFail"), solver)
}

func TestRenderPageEscapesAndSanitizesRet(t *testing.T) {
	html := renderPage("T", 8, "/v", `/a?q="><script>x</script>`, 0)
	require.NotContains(t, html, `"><script>x`)
	require.Contains(t, html, `/a?q=&#34;&gt;&lt;script&gt;x&lt;/script&gt;`)

	for _, bad := range []string{"//evil.com", "/\\evil.com", "https://evil.com", "/\t/evil.com"} {
		out := renderPage("T", 8, "/v", bad, 0)
		require.Contains(t, out, `name="ret" value="/"`, bad)
	}
}

func TestRenderFailedPage(t *testing.T) {
	html := renderFailedPage("/dashboard", false)
	require.Contains(t, html, "We couldn't confirm your browser")
	require.Contains(t, html, `data-reason="failed"`)
	require.Contains(t, html, "it didn't pass")
	require.Contains(t, html, "contact the owner of this site")
	require.Contains(t, html, `href="/dashboard"`)
	require.Contains(t, html, "<style>")
	require.NotContains(t, html, "{{")
	require.Contains(t, renderFailedPage("//evil.com", false), `href="/"`)

	kept := renderFailedPage("/dashboard", true)
	require.Contains(t, kept, `data-reason="not_kept"`)
	require.Contains(t, kept, "cookies are blocked for this site")
	require.NotContains(t, kept, "it didn't pass")
	require.NotContains(t, kept, "{{")
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

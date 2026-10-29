package apxchallenge

import (
	_ "embed"
	"html"
	"strconv"
	"strings"
)

//go:embed assets/challenge.html
var pageHTML string

//go:embed assets/pow.js
var powJS string

//go:embed assets/challenge.css
var pageCSS string

//go:embed assets/verify_widget.js
var verifyWidgetJS string

// defaultChallengeTimeoutMs is how long the page waits for the solver before
// it swaps the spinner for the "didn't finish" panel with a Retry button.
const defaultChallengeTimeoutMs = 20000

// renderPage inlines the CSS + JS and injects the per-request challenge token,
// difficulty, verify path, return path and solver timeout. One self-contained
// HTML response — no separate asset routes to wire. ret is HTML-escaped (it
// lands in attribute values); timeoutMs <= 0 means the default.
func renderPage(challengeToken string, difficulty int, verifyPath, ret string, timeoutMs int) string {
	if timeoutMs <= 0 {
		timeoutMs = defaultChallengeTimeoutMs
	}
	return strings.NewReplacer(
		"{{CSS}}", pageCSS,
		"{{JS}}", powJS,
		"{{CHALLENGE}}", challengeToken,
		"{{DIFFICULTY}}", strconv.Itoa(difficulty),
		"{{VERIFY_PATH}}", verifyPath,
		"{{RET}}", html.EscapeString(safeReturn(ret)),
		"{{TIMEOUT_MS}}", strconv.Itoa(timeoutMs),
	).Replace(pageHTML)
}

// failedPageHTML is served (200) when a browser has failed verification
// maxVerifyTries times in a row, instead of redirecting to yet another
// challenge. Same stylesheet as the challenge page.
const failedPageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>We couldn't confirm your browser</title>
<style>{{CSS}}</style>
</head>
<body>
<main class="box" id="apx-gave-up">
<h1>We couldn't confirm your browser</h1>
<p>This site checks browsers before letting them in. Your browser tried the check several times in the last few minutes and it didn't pass.</p>
<p class="muted">This can happen when your network address changes during the check (for example on a VPN or mobile data), when the page was left open for a long time, or when an extension blocks scripts.</p>
<p class="muted">You can try again now or in a few minutes. If it keeps happening, contact the owner of this site.</p>
<p><a class="button" href="{{RET}}">Try again</a></p>
</main>
</body>
</html>
`

// renderFailedPage renders the "gave up after repeated failures" page with a
// Retry link to the (sanitized) original path.
func renderFailedPage(ret string) string {
	return strings.NewReplacer(
		"{{CSS}}", pageCSS,
		"{{RET}}", html.EscapeString(safeReturn(ret)),
	).Replace(failedPageHTML)
}

// renderVerifyWidget substitutes the endpoint paths into the embedded widget.
// Served as application/javascript with a long cache + ETag by the handler.
func renderVerifyWidget(challengePath, tokenPath string) string {
	return strings.NewReplacer(
		"{{CHALLENGE_PATH}}", challengePath,
		"{{TOKEN_PATH}}", tokenPath,
	).Replace(verifyWidgetJS)
}

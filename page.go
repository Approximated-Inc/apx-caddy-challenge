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

// defaultChallengeTimeoutMs is how long the page shows the plain spinner.
// After it the page says "Still checking…" while the solver keeps reporting
// progress, and shows the failure panel only once progress stops. Because
// failure is decided by stalled progress, not elapsed time, this value need
// not scale with difficulty: it is only when a visitor starts to wonder.
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

// failedPageHTML is served (200) instead of another challenge once a browser
// has failed, or passed without keeping the pass cookie, maxVerifyTries times
// in a row. Same stylesheet as the challenge page.
const failedPageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>We couldn't confirm your browser</title>
<style>{{CSS}}</style>
</head>
<body>
<main class="box" id="apx-gave-up" data-reason="{{REASON}}">
<h1>We couldn't confirm your browser</h1>
{{BODY}}
<p class="muted">You can try again now or in a few minutes. If it keeps happening, contact the owner of this site.</p>
<p><a class="button" href="{{RET}}">Try again</a></p>
</main>
</body>
</html>
`

const failedBody = `<p>This site checks browsers before letting them in. Your browser tried the check several times in the last few minutes and it didn't pass.</p>
<p class="muted">This can happen when your network address changes during the check (for example on a VPN or mobile data), when the page was left open for a long time, or when an extension blocks scripts.</p>`

const notKeptBody = `<p>This site checks browsers before letting them in. Your browser passed the check several times, but the site couldn't see that on the next page, so it kept asking.</p>
<p class="muted">This happens when cookies are blocked for this site, when the site is shown inside another site, or when your network address keeps changing (for example on a VPN or mobile data). Allowing cookies for this site or opening it directly usually fixes it.</p>`

// renderFailedPage renders the loop-ending explanation page with a Retry link
// to the (sanitized) original path.
func renderFailedPage(ret string, passedButNotKept bool) string {
	reason, body := "failed", failedBody
	if passedButNotKept {
		reason, body = "not_kept", notKeptBody
	}
	return strings.NewReplacer(
		"{{CSS}}", pageCSS,
		"{{RET}}", html.EscapeString(safeReturn(ret)),
		"{{REASON}}", reason,
		"{{BODY}}", body,
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

package apxchallenge

import (
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	cookieTTL         = 10 * time.Minute
	challengeTokenTTL = 5 * time.Minute
	outcomeVarKey     = "apx_challenge_outcome"
	reasonVarKey      = "apx_challenge_reason"
)

// Reasons recorded in apx_challenge_reason beside an issued or failed outcome.
// apx-caddy-stats composes them into the stored outcome (issued_document,
// not_shown_api, failed_proof, ...). The outcome var itself keeps its five
// values, which the response guard route and request-event dispositions match.
const (
	reasonDocument        = "document"         // issued: page served to a likely displayed document
	reasonOther           = "other"            // issued: page served to anything else (HEAD, subresource, */*)
	reasonAPI             = "api"              // failed: 429, no page shown to a likely API client
	reasonStream          = "stream"           // failed: 503, no page shown to WebSocket or SSE
	reasonToken           = "token"            // failed: token missing, malformed or forged
	reasonExpired         = "expired"          // failed: authentic token past its life
	reasonBinding         = "binding"          // failed: authentic token for another client prefix or UA
	reasonProof           = "proof"            // failed: valid token, wrong proof-of-work
	reasonStaleDifficulty = "stale_difficulty" // failed: proof meets the difficulty before a recent change, not the current one
	reasonReplay          = "replay"           // failed: valid proof-of-work solve already spent
	reasonRenderCookie    = "render_cookie"    // failed: fallback POST without the fallback cookie naming its nonce
	reasonRenderPixel     = "render_pixel"     // failed: fallback POST whose pixel was not loaded on this machine
	reasonRenderDwell     = "render_dwell"     // failed: fallback POST before the minimum dwell
	reasonFallbackReplay  = "fallback_replay"  // failed: fallback nonce already spent (a double-clicked Continue)
	reasonFallbackLimit   = "fallback_limit"   // failed: fallback budget for the prefix used up
	reasonFallback        = "fallback"         // passed_recently: the pass cookie was earned through the fallback
)

// ChallengeHandler serves the PoW challenge / verifies solutions. Invoked by the
// per-dimension challenge routes (and the verify route) Phoenix emits.
type ChallengeHandler struct {
	logger *zap.Logger
	app    AppRef
}

func (*ChallengeHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apx_challenge",
		New: func() caddy.Module { return new(ChallengeHandler) },
	}
}

func (h *ChallengeHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.app == nil {
		app, err := ctx.App("apx_challenge")
		if err != nil {
			return fmt.Errorf("apx_challenge handler requires apx_challenge app: %w", err)
		}
		ca, ok := app.(*ChallengeApp)
		if !ok {
			return fmt.Errorf("apx_challenge handler: unexpected app type %T", app)
		}
		h.app = ca
	}
	return nil
}

func (h *ChallengeHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (h *ChallengeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := clientIP(r)

	if r.Method == http.MethodPost && r.URL.Path == h.app.VerifyPath() {
		return h.handleVerify(w, r, ip)
	}
	if h.app.Fallback().Enabled && isFallbackPixelRequest(r, h.app.VerifyPath()) {
		return h.serveFallbackPixel(w, r)
	}

	if c, err := r.Cookie(CookieName); err == nil {
		pol, now := h.app.PassPolicy(), time.Now()
		if pc, ok := VerifyPassCookie(h.app.Secret(), pol, c.Value, ip, r.UserAgent(), now); ok {
			if exp, renew := pol.Renewal(pc, now); renew {
				setPassCookie(w, issuePassCookie(h.app.Secret(), pol, ip, r.UserAgent(), pc.IssuedAt, exp, pc.Fallback), exp, now)
			}
			if pc.Fallback {
				setOutcomeReason(r, "passed_recently", reasonFallback)
			} else {
				setOutcome(r, "passed_recently")
			}
			clearTriesCookie(w, r) // apx-challenge-failure-states: pass cookie works, reset the loop breaker
			// valid proof — forward to this route's upstream (the reverse_proxy after this terminal handler)
			return next.ServeHTTP(w, r)
		}
	}

	if isWebSocketOrSSE(r) {
		setOutcomeReason(r, "failed", reasonStream)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil
	}
	if isLikelyAPIClient(r) {
		setOutcomeReason(r, "failed", reasonAPI)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"challenge_required","retry_after":30}`))
		return nil
	}

	if r.Method != http.MethodHead && isLikelyDocument(r) && !isPrefetch(r) {
		setOutcomeReason(r, "issued", reasonDocument)
	} else {
		setOutcomeReason(r, "issued", reasonOther)
	}
	now := time.Now()
	ret := safeReturn(r.URL.RequestURI())
	tok := IssuePassChallenge(h.app.Secret(), h.app.PassPolicy(), ip, r.UserAgent(), ret, now.Add(challengeTokenTTL))
	var fb *fallbackView
	if h.app.Fallback().Enabled && isLikelyDocument(r) {
		pol := h.app.PassPolicy()
		ftok, nonce := issueFallbackToken(h.app.Secret(), pol, ip, r.UserAgent(), ret, now)
		setFallbackCookie(w, h.app.Secret(), withNonce(readFallbackNonces(r, h.app.Secret()), nonce))
		pixel := fallbackPixelURL(h.app.Secret(), h.app.VerifyPath(), pol, ip, r.UserAgent(), nonce, now.Add(fallbackTokenTTL).Unix())
		fb = &fallbackView{Token: ftok, PixelURL: pixel, VerifyPath: h.app.VerifyPath(), Ret: ret}
	}
	body := renderChallengePage(tok, h.app.Difficulty(), h.app.VerifyPath(), r.URL.RequestURI(), defaultChallengeTimeoutMs, fb)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
	return nil
}

func (h *ChallengeHandler) handleVerify(w http.ResponseWriter, r *http.Request, ip string) error {
	_ = r.ParseForm()
	if h.app.Fallback().Enabled && r.FormValue("mode") == fallbackModeValue {
		return h.handleFallbackVerify(w, r, ip)
	}
	challenge := r.FormValue("challenge")
	solution := r.FormValue("solution")

	pol, now := h.app.PassPolicy(), time.Now()
	p, err := VerifyPassChallenge(h.app.Secret(), pol, challenge, ip, r.UserAgent(), now)
	reason := tokenFailureReason(err)
	switch {
	case reason != "":
	case !VerifyPoW(challenge, solution, h.app.Difficulty()):
		reason = reasonProof
		// Solved at a difficulty in force during the last few minutes: the
		// page may have been issued with it, so the visitor did nothing wrong.
		for _, prev := range h.app.PreviousDifficulties(now) {
			if VerifyPoW(challenge, solution, prev) {
				reason = reasonStaleDifficulty
				break
			}
		}
	case h.replayedSolve(pol, p): // only after the token and proof verify: it spends the solve
		reason = reasonReplay
	}
	if reason != "" {
		// The token's return path when it still verifies, else the page's
		// hidden ret field (an expired or IP-mismatched token can't be trusted).
		ret := safeReturn(r.FormValue("ret"))
		if err == nil {
			ret = safeReturn(p.Ret)
		}
		return h.verifyFailed(w, r, ret, reason)
	}
	// The cap counts from the challenge's issue, so replaying a token can't reset it.
	iat := p.IssuedAt(challengeTokenTTL)
	exp := pol.InitialExp(iat, now)
	setPassCookie(w, IssuePassCookie(h.app.Secret(), pol, ip, r.UserAgent(), iat, exp), exp, now)
	setOutcome(r, "passed")
	return h.verifyPassed(w, r, safeReturn(p.Ret))
}

// tokenFailureReason names why a challenge or fallback token did not verify,
// or "" when it did.
func tokenFailureReason(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errExpired):
		return reasonExpired
	case errors.Is(err, errBinding):
		return reasonBinding
	default:
		return reasonToken
	}
}

// verifyFailed answers a failed verify: a bare 403 for scripts; for a browser
// form post, a counted failure in the tries cookie plus a redirect to a fresh
// challenge at ret (the explanation page at the threshold). reason is recorded
// beside the failed outcome.
func (h *ChallengeHandler) verifyFailed(w http.ResponseWriter, r *http.Request, ret, reason string) error {
	setOutcomeReason(r, "failed", reason)
	if !isBrowserFormPost(r) {
		w.WriteHeader(http.StatusForbidden)
		return nil
	}
	st := readTries(r, h.app.Secret())
	st.countFailure()
	writeTries(w, h.app.Secret(), st)
	if st.Failed >= maxVerifyTries {
		writeGaveUpPage(w, ret, false)
		return nil
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Location", ret)
	w.WriteHeader(http.StatusSeeOther)
	return nil
}

// verifyPassed finishes a pass once the pass cookie is set: count it in the
// tries cookie, then redirect to ret (or the continue / explanation page).
func (h *ChallengeHandler) verifyPassed(w http.ResponseWriter, r *http.Request, ret string) error {
	st := readTries(r, h.app.Secret())
	counted := st.countPass(time.Now())
	writeTries(w, h.app.Secret(), st)
	if st.Passed >= maxVerifyTries {
		// Passed repeatedly but never came back with the pass cookie.
		writeGaveUpPage(w, ret, true)
		return nil
	}
	if !counted {
		// Another pass in the same round (other tab, Retry, or a loop):
		// continue after a pause rather than at once, so a loop is slowed.
		writeContinuePage(w, ret)
		return nil
	}
	w.Header().Set("Location", ret)
	w.WriteHeader(http.StatusSeeOther)
	return nil
}

// replayedSolve marks a verified solve as spent and reports whether it was
// already spent. Under a non-default policy a solved challenge is single-use
// per machine, so one solve can't mint a cookie per address or UA; a replay
// takes the failure path (403, or the browser recovery redirect). The default
// policy keeps solves reusable, as before.
func (h *ChallengeHandler) replayedSolve(pol PassPolicy, p ChallengePayload) bool {
	return pol != DefaultPassPolicy() && h.app.ReplayLRU().Seen("chal:"+p.Nonce)
}

// writeContinuePage serves the 200 "Continuing…" page that sends the browser
// on to ret after continueDelay (meta refresh, plus a link without it).
func writeContinuePage(w http.ResponseWriter, ret string) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(renderContinuePage(ret, int(continueDelay.Seconds()))))
}

// writeGaveUpPage serves the explanation page (200) that ends a challenge
// loop. passedButNotKept selects the copy for a browser that passes the check
// but never keeps the pass cookie.
func writeGaveUpPage(w http.ResponseWriter, ret string, passedButNotKept bool) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(renderFailedPage(ret, passedButNotKept)))
}

// isBrowserFormPost reports whether a verify POST came from a page navigation
// (the challenge form) rather than a script or API client. Those get a
// recovery redirect on failure; everything else keeps the bare 403.
func isBrowserFormPost(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
		return true
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		return true
	}
	if r.Header.Get("Sec-Fetch-Mode") != "" || r.Header.Get("Sec-Fetch-Site") != "" ||
		r.Header.Get("Sec-Fetch-Dest") != "" || r.Header.Get("Sec-Fetch-User") != "" {
		return false
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/x-www-form-urlencoded"
}

func setOutcome(r *http.Request, outcome string) {
	caddyhttp.SetVar(r.Context(), outcomeVarKey, outcome)
}

// setOutcomeReason sets the outcome and the reason recorded beside it.
func setOutcomeReason(r *http.Request, outcome, reason string) {
	setOutcome(r, outcome)
	caddyhttp.SetVar(r.Context(), reasonVarKey, reason)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// safeReturn prevents open-redirects: only same-origin absolute paths. Rejects
// scheme-relative ("//host"), absolute URLs, backslash variants ("/\\host")
// that browsers normalize to "//host", and any control character (browsers
// strip tab/newline from URLs, so "/\t/host" becomes "//host"). Anything
// else → "/".
func safeReturn(ret string) string {
	if !strings.HasPrefix(ret, "/") ||
		strings.HasPrefix(ret, "//") ||
		strings.HasPrefix(ret, "/\\") {
		return "/"
	}
	for i := 0; i < len(ret); i++ {
		if ret[i] < 0x20 || ret[i] == 0x7f {
			return "/"
		}
	}
	return ret
}

// isPrefetch reports a speculative fetch (Sec-Purpose: prefetch, possibly
// with prerender, or the older Purpose: prefetch) that the visitor may never see.
func isPrefetch(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Sec-Purpose")), "prefetch") ||
		strings.EqualFold(r.Header.Get("Purpose"), "prefetch")
}

func isWebSocketOrSSE(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return true
	}
	return strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

// isLikelyAPIClient flags requests that won't run JS. Conservative — only
// diverts obvious non-document requests so real browsers always get the page.
func isLikelyAPIClient(r *http.Request) bool {
	if m := r.Header.Get("Sec-Fetch-Mode"); m == "cors" || m == "no-cors" {
		if d := r.Header.Get("Sec-Fetch-Dest"); d != "" && d != "document" {
			return true
		}
	}
	accept := r.Header.Get("Accept")
	if accept != "" && !strings.Contains(accept, "text/html") && !strings.Contains(accept, "*/*") {
		return true
	}
	return false
}

var (
	_ caddy.Provisioner           = (*ChallengeHandler)(nil)
	_ caddyfile.Unmarshaler       = (*ChallengeHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ChallengeHandler)(nil)
)

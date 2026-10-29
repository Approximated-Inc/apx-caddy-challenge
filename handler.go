package apxchallenge

import (
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

	if c, err := r.Cookie(CookieName); err == nil && VerifyCookie(h.app.Secret(), c.Value, ip) {
		setOutcome(r, "passed_recently")
		clearTriesCookie(w, r) // apx-challenge-failure-states: pass cookie works, reset the loop breaker
		// valid proof — forward to this route's upstream (the reverse_proxy after this terminal handler)
		return next.ServeHTTP(w, r)
	}

	if isWebSocketOrSSE(r) {
		setOutcome(r, "failed")
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
		return nil
	}
	if isLikelyAPIClient(r) {
		setOutcome(r, "failed")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"challenge_required","retry_after":30}`))
		return nil
	}

	setOutcome(r, "issued")
	tok := IssueChallenge(h.app.Secret(), ip, safeReturn(r.URL.RequestURI()), time.Now().Add(challengeTokenTTL))
	body := renderPage(tok, h.app.Difficulty(), h.app.VerifyPath(), r.URL.RequestURI(), defaultChallengeTimeoutMs)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
	return nil
}

func (h *ChallengeHandler) handleVerify(w http.ResponseWriter, r *http.Request, ip string) error {
	_ = r.ParseForm()
	challenge := r.FormValue("challenge")
	solution := r.FormValue("solution")

	p, err := VerifyChallenge(h.app.Secret(), challenge, ip)
	if err != nil || !VerifyPoW(challenge, solution, h.app.Difficulty()) {
		setOutcome(r, "failed")
		if !isBrowserFormPost(r) {
			w.WriteHeader(http.StatusForbidden)
			return nil
		}
		// The token's return path when it still verifies, else the page's
		// hidden ret field (an expired or IP-mismatched token can't be trusted).
		ret := safeReturn(r.FormValue("ret"))
		if err == nil {
			ret = safeReturn(p.Ret)
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
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    IssueCookie(h.app.Secret(), ip, time.Now().Add(cookieTTL)),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(cookieTTL.Seconds()),
	})
	setOutcome(r, "passed")
	st := readTries(r, h.app.Secret())
	counted := st.countPass(time.Now())
	writeTries(w, h.app.Secret(), st)
	if st.Passed >= maxVerifyTries {
		// Passed repeatedly but never came back with the pass cookie.
		writeGaveUpPage(w, safeReturn(p.Ret), true)
		return nil
	}
	if !counted {
		// Another pass in the same round (other tab, Retry, or a loop):
		// continue after a pause rather than at once, so a loop is slowed.
		writeContinuePage(w, safeReturn(p.Ret))
		return nil
	}
	w.Header().Set("Location", safeReturn(p.Ret))
	w.WriteHeader(http.StatusSeeOther)
	return nil
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

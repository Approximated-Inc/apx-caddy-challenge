package apxchallenge

import (
	"fmt"
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

	if c, err := r.Cookie(CookieName); err == nil {
		pol, now := h.app.PassPolicy(), time.Now()
		if pc, ok := VerifyPassCookie(h.app.Secret(), pol, c.Value, ip, r.UserAgent(), now); ok {
			if exp, renew := pol.Renewal(pc, now); renew {
				setPassCookie(w, IssuePassCookie(h.app.Secret(), pol, ip, r.UserAgent(), pc.IssuedAt, exp), exp, now)
			}
			setOutcome(r, "passed_recently")
			// valid proof — forward to this route's upstream (the reverse_proxy after this terminal handler)
			return next.ServeHTTP(w, r)
		}
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
	body := renderPage(tok, h.app.Difficulty(), h.app.VerifyPath())
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
		w.WriteHeader(http.StatusForbidden)
		return nil
	}
	pol, now := h.app.PassPolicy(), time.Now()
	exp := now.Add(pol.IdleTTL)
	setPassCookie(w, IssuePassCookie(h.app.Secret(), pol, ip, r.UserAgent(), now, exp), exp, now)
	setOutcome(r, "passed")
	w.Header().Set("Location", safeReturn(p.Ret))
	w.WriteHeader(http.StatusSeeOther)
	return nil
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
// scheme-relative ("//host"), absolute URLs, and backslash variants ("/\\host")
// that browsers normalize to "//host". Anything else → "/".
func safeReturn(ret string) string {
	if strings.HasPrefix(ret, "/") &&
		!strings.HasPrefix(ret, "//") &&
		!strings.HasPrefix(ret, "/\\") {
		return ret
	}
	return "/"
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

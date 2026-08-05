package apxchallenge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

const (
	// verifyOutcomeVarKey is the caddyhttp var the protection handler writes for
	// downstream logging/analytics.
	verifyOutcomeVarKey = "apx_verify_outcome"
	// verifyTokenField is the hidden form field the widget injects.
	verifyTokenField = "_apx_verify_token"
	// verifyTokenHeader carries the token for fetch/JSON submitters.
	verifyTokenHeader = "X-Apx-Verify-Token"

	verifyWidgetPath    = "/__apx_verify/widget.js"
	verifyChallengePath = "/__apx_verify/challenge"
	verifyTokenPath     = "/__apx_verify/token"

	// verifyWidgetVersion bumps whenever assets/verify_widget.js or the substituted
	// paths change; it is the ETag basis so caches revalidate on a new build.
	verifyWidgetVersion = "2"
)

// ---------------------------------------------------------------------------
// VerifyEndpointHandler — terminal handler for the three widget endpoints.
// ---------------------------------------------------------------------------

// VerifyEndpointHandler serves the Edge Verify widget script and the
// challenge/token minting endpoints. It is terminal: it always writes a
// response and never calls next.
type VerifyEndpointHandler struct {
	logger *zap.Logger
	app    AppRef
}

func (*VerifyEndpointHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apx_verify_endpoints",
		New: func() caddy.Module { return new(VerifyEndpointHandler) },
	}
}

func (h *VerifyEndpointHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.app == nil {
		app, err := resolveApp(ctx)
		if err != nil {
			return err
		}
		h.app = app
	}
	return nil
}

func (h *VerifyEndpointHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (h *VerifyEndpointHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == verifyWidgetPath:
		return h.serveWidget(w, r)
	case r.Method == http.MethodPost && r.URL.Path == verifyChallengePath:
		return h.serveChallenge(w, r)
	case r.Method == http.MethodPost && r.URL.Path == verifyTokenPath:
		return h.serveToken(w, r)
	}
	w.WriteHeader(http.StatusNotFound)
	return nil
}

func (h *VerifyEndpointHandler) serveWidget(w http.ResponseWriter, r *http.Request) error {
	etag := `"apxverify-` + verifyWidgetVersion + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if match := r.Header.Get("If-None-Match"); match == etag {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	body := renderVerifyWidget(verifyChallengePath, verifyTokenPath)
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, body)
	return nil
}

func (h *VerifyEndpointHandler) serveChallenge(w http.ResponseWriter, r *http.Request) error {
	ip := clientIP(r)
	difficulty := h.app.VerifyDifficulty()
	challenge := IssueVerifyChallenge(h.app.Secret(), ip, difficulty, time.Now().Add(h.app.VerifyTokenTTL()))
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":  challenge,
		"difficulty": difficulty,
	})
	return nil
}

func (h *VerifyEndpointHandler) serveToken(w http.ResponseWriter, r *http.Request) error {
	ip := clientIP(r)
	_ = r.ParseForm()
	challenge := r.FormValue("challenge")
	solution := r.FormValue("solution")
	probesRaw := r.FormValue("probes")

	payload, err := CheckVerifyChallenge(h.app.Secret(), challenge, ip)
	if err != nil {
		return h.refuse(w, r, "challenge_invalid", "bad_challenge")
	}
	if !VerifyPoW(challenge, solution, payload.Diff) {
		return h.refuse(w, r, "pow_invalid", "bad_solution")
	}

	var probes Probes
	if err := json.Unmarshal([]byte(probesRaw), &probes); err != nil {
		return h.refuse(w, r, "probes_invalid", "bad_probes")
	}
	if ok, reason := ScoreProbes(probes, h.app.VerifyScoring()); !ok {
		return h.refuse(w, r, "probe_failed", reason)
	}

	// Hostnames are case-insensitive; lowercase so mint and verify always match.
	host := strings.ToLower(hostOnly(r.Host))
	ttl := h.app.VerifyTokenTTL()
	token := IssueVerifyToken(h.app.Secret(), ip, host, payload.Nonce, time.Now().Add(ttl))
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_in": int(ttl.Seconds()),
	})
	return nil
}

// refuse writes a 200 with {error, reason} and NO token. The widget injects
// nothing, so the later protected POST is blocked. 200 (not 4xx) keeps the
// widget's fail-open path from surfacing errors to the page.
//
// It logs the reason at Debug, so the line is visible only where the cluster's
// log level includes Debug: the fleet default (ProxyServer.log_level) is ERROR,
// so a default cluster stays silent; the dev cluster runs DEBUG. A fleet-visible
// counter/metric is the real follow-up. The historical motivation stands: the
// too_fast bug refused 100% of real mints yet left no server-side trace, so it
// survived until hands-on testing — a sustained spike in probe_failed here means
// real users are being blocked.
func (h *VerifyEndpointHandler) refuse(w http.ResponseWriter, r *http.Request, errCode, reason string) error {
	if h.logger != nil {
		h.logger.Debug("apx_verify: token mint refused",
			zap.String("error", errCode), zap.String("reason", reason),
			zap.String("host", hostOnly(r.Host)))
	}
	writeJSON(w, http.StatusOK, map[string]any{"error": errCode, "reason": reason})
	return nil
}

// ---------------------------------------------------------------------------
// VerifyHandler — gates the matched protected POST.
// ---------------------------------------------------------------------------

// VerifyHandler validates the injected token on a request the config-gen
// route already scoped to a protected path+method. Mode is "enforce" (block
// non-passing) or "monitor" (record outcome, always forward).
type VerifyHandler struct {
	Mode string `json:"mode,omitempty"`

	logger *zap.Logger
	app    AppRef
	replay *NonceLRU
}

func (*VerifyHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.apx_verify",
		New: func() caddy.Module { return new(VerifyHandler) },
	}
}

func (h *VerifyHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.app == nil {
		app, err := resolveApp(ctx)
		if err != nil {
			return err
		}
		h.app = app
	}
	if h.replay == nil {
		h.replay = h.app.ReplayLRU()
	}
	if h.Mode != "monitor" {
		h.Mode = "enforce"
	}
	return nil
}

func (h *VerifyHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (h *VerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := clientIP(r)
	// Hostnames are case-insensitive; lowercase so mint and verify always match.
	host := strings.ToLower(hostOnly(r.Host))

	token := h.extractToken(r)
	outcome := "missing"
	if token != "" {
		if p, err := CheckVerifyToken(h.app.Secret(), token, ip, host); err != nil {
			// CheckVerifyToken folds expiry into a generic invalid error; we do not
			// separately emit "expired" (see task report).
			outcome = "invalid"
		} else if h.replay.Seen(p.Nonce) {
			outcome = "replayed"
		} else {
			outcome = "passed"
		}
	}
	setVerifyOutcome(r, outcome)

	if h.Mode == "monitor" || outcome == "passed" {
		return next.ServeHTTP(w, r)
	}
	return h.block(w, r)
}

func (h *VerifyHandler) block(w http.ResponseWriter, r *http.Request) error {
	if isLikelyAPIClient(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"edge_verify_failed"}`)
		return nil
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, "<!doctype html><meta charset=utf-8><title>Blocked</title><p>This form submission was blocked.</p>")
	return nil
}

// extractToken returns the verify token from the X-Apx-Verify-Token header (always
// honored) or, for urlencoded/multipart bodies within the cap, from the parsed
// body. When it reads the body it RESTORES it so reverse_proxy forwards the
// untouched request; an over-cap or unknown-length body is left untouched and
// only the header is consulted.
func (h *VerifyHandler) extractToken(r *http.Request) string {
	if t := r.Header.Get(verifyTokenHeader); t != "" {
		return t
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/x-www-form-urlencoded" && mediaType != "multipart/form-data") {
		return ""
	}
	if r.Body == nil {
		return ""
	}
	bodyCap := h.app.VerifyBodyCap()
	// Unknown length (chunked) or over-cap: skip body parsing, leave body intact.
	if r.ContentLength < 0 || r.ContentLength > bodyCap {
		return ""
	}

	// ContentLength is within cap; buffer it (bounded) and restore for upstream.
	buf, err := io.ReadAll(io.LimitReader(r.Body, bodyCap))
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(buf))
		r.ContentLength = int64(len(buf))
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))

	return tokenFromBody(mediaType, r.Header.Get("Content-Type"), buf, bodyCap)
}

func tokenFromBody(mediaType, contentType string, buf []byte, bodyCap int64) string {
	switch mediaType {
	case "application/x-www-form-urlencoded":
		vals, err := url.ParseQuery(string(buf))
		if err != nil {
			return ""
		}
		return vals.Get(verifyTokenField)
	case "multipart/form-data":
		_, params, err := mime.ParseMediaType(contentType)
		if err != nil {
			return ""
		}
		boundary := params["boundary"]
		if boundary == "" {
			return ""
		}
		form, err := multipart.NewReader(bytes.NewReader(buf), boundary).ReadForm(bodyCap)
		if err != nil {
			return ""
		}
		defer func() { _ = form.RemoveAll() }()
		if vs := form.Value[verifyTokenField]; len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

func resolveApp(ctx caddy.Context) (AppRef, error) {
	app, err := ctx.App("apx_challenge")
	if err != nil {
		return nil, fmt.Errorf("apx_verify handler requires apx_challenge app: %w", err)
	}
	ca, ok := app.(*ChallengeApp)
	if !ok {
		return nil, fmt.Errorf("apx_verify handler: unexpected app type %T", app)
	}
	return ca, nil
}

func setVerifyOutcome(r *http.Request, outcome string) {
	caddyhttp.SetVar(r.Context(), verifyOutcomeVarKey, outcome)
}

// hostOnly strips any port from a Host header value.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

var (
	_ caddy.Provisioner           = (*VerifyEndpointHandler)(nil)
	_ caddyfile.Unmarshaler       = (*VerifyEndpointHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*VerifyEndpointHandler)(nil)

	_ caddy.Provisioner           = (*VerifyHandler)(nil)
	_ caddyfile.Unmarshaler       = (*VerifyHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*VerifyHandler)(nil)
)

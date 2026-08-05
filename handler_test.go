package apxchallenge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

type fakeApp struct {
	sec  string
	diff int
	vp   string
}

func (f fakeApp) Secret() string     { return f.sec }
func (f fakeApp) Difficulty() int    { return f.diff }
func (f fakeApp) VerifyPath() string { return f.vp }

func (f fakeApp) VerifyDifficulty() int         { return 14 }
func (f fakeApp) VerifyTokenTTL() time.Duration { return 600 * time.Second }
func (f fakeApp) VerifyScoring() string         { return "lenient" }
func (f fakeApp) VerifyBodyCap() int64          { return 1048576 }
func (f fakeApp) ReplayLRU() *NonceLRU          { return NewNonceLRU(1024) }

func newHandler() *ChallengeHandler {
	return &ChallengeHandler{app: fakeApp{sec: "h-secret", diff: 8, vp: "/__apx_challenge/verify"}}
}

var nextOK = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(200)
	_, _ = io.WriteString(w, "UPSTREAM")
	return nil
})

// withVars seeds the caddyhttp vars map so setOutcome's SetVar doesn't panic.
func withVars(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
}

func browserReq(path string) *http.Request {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "203.0.113.5:443"
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Accept-Language", "en-US")
	return withVars(r)
}

func timeNowPlus10() time.Time { return time.Now().Add(10 * time.Minute) }

func TestServePageForBrowserNoCookie(t *testing.T) {
	h := newHandler()
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, browserReq("/dashboard"), nextOK))
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "apx-challenge")
	require.Equal(t, "private, no-store", w.Result().Header.Get("Cache-Control"))
}

func TestValidCookiePassesThrough(t *testing.T) {
	h := newHandler()
	r := browserReq("/dashboard")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: IssueCookie("h-secret", "203.0.113.5", timeNowPlus10())})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Equal(t, "UPSTREAM", w.Body.String())
}

func TestNonBrowserGets429(t *testing.T) {
	h := newHandler()
	r := httptest.NewRequest("GET", "/api/x", nil)
	r.RemoteAddr = "203.0.113.5:443"
	r.Header.Set("Accept", "application/json")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, withVars(r), nextOK))
	require.Equal(t, 429, w.Code)
	require.Contains(t, w.Body.String(), "challenge_required")
}

func TestWebSocketGets503(t *testing.T) {
	h := newHandler()
	r := browserReq("/ws")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Equal(t, 503, w.Code)
	require.Equal(t, "30", w.Result().Header.Get("Retry-After"))
}

func TestVerifySuccessSetsCookieAndRedirects(t *testing.T) {
	h := newHandler()
	tok := IssueChallenge("h-secret", "203.0.113.5", "/dashboard", timeNowPlus10())
	sol := SolvePoW(tok, 8)
	form := url.Values{"challenge": {tok}, "solution": {sol}}
	r := httptest.NewRequest("POST", "/__apx_challenge/verify", strings.NewReader(form.Encode()))
	r.RemoteAddr = "203.0.113.5:443"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, withVars(r), nextOK))
	require.Equal(t, 303, w.Code)
	require.Equal(t, "/dashboard", w.Result().Header.Get("Location"))
	require.NotEmpty(t, w.Result().Cookies())
	require.Equal(t, CookieName, w.Result().Cookies()[0].Name)
}

func TestVerifyFailureReturns403(t *testing.T) {
	h := newHandler()
	tok := IssueChallenge("h-secret", "203.0.113.5", "/x", timeNowPlus10())
	form := url.Values{"challenge": {tok}, "solution": {"wrong"}}
	r := httptest.NewRequest("POST", "/__apx_challenge/verify", strings.NewReader(form.Encode()))
	r.RemoteAddr = "203.0.113.5:443"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, withVars(r), nextOK))
	require.Equal(t, 403, w.Code)
}

func TestSafeReturn(t *testing.T) {
	require.Equal(t, "/dashboard", safeReturn("/dashboard"))
	require.Equal(t, "/a/b?x=1", safeReturn("/a/b?x=1"))
	require.Equal(t, "/", safeReturn("//evil.com"))
	require.Equal(t, "/", safeReturn("/\\evil.com")) // backslash bypass
	require.Equal(t, "/", safeReturn("https://evil.com"))
	require.Equal(t, "/", safeReturn("javascript:alert(1)"))
	require.Equal(t, "/", safeReturn(""))
}

func TestVerifyRedirectIsSanitized(t *testing.T) {
	h := newHandler()
	tok := IssueChallenge("h-secret", "203.0.113.5", "/\\evil.com", timeNowPlus10())
	sol := SolvePoW(tok, 8)
	form := url.Values{"challenge": {tok}, "solution": {sol}}
	r := httptest.NewRequest("POST", "/__apx_challenge/verify", strings.NewReader(form.Encode()))
	r.RemoteAddr = "203.0.113.5:443"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, withVars(r), nextOK))
	require.Equal(t, 303, w.Code)
	require.Equal(t, "/", w.Result().Header.Get("Location"))
}

func TestOutcomeVarSet(t *testing.T) {
	h := newHandler()
	r := browserReq("/x")
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	vars := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any)
	require.Equal(t, "issued", vars["apx_challenge_outcome"])
}

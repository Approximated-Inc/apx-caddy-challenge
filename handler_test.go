package apxchallenge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
	r.Header.Set("Sec-Fetch-Mode", "cors") // a script, not the challenge form
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, withVars(r), nextOK))
	require.Equal(t, 403, w.Code)
}

// verifyPost builds a verify POST. browser=true mimics Chromium submitting the
// challenge form (navigate + text/html Accept).
func verifyPost(form url.Values, browser bool, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest("POST", "/__apx_challenge/verify", strings.NewReader(form.Encode()))
	r.RemoteAddr = "203.0.113.5:443"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if browser {
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		r.Header.Set("Accept", "text/html,application/xhtml+xml")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return withVars(r)
}

func triesCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == triesCookieName {
			return c
		}
	}
	return nil
}

func expiredForm(ret string) url.Values {
	tok := IssueChallenge("h-secret", "203.0.113.5", ret, time.Now().Add(-time.Minute))
	return url.Values{"challenge": {tok}, "solution": {SolvePoW(tok, 8)}, "ret": {ret}}
}

func TestBrowserVerifyExpiredTokenRedirectsToFreshChallenge(t *testing.T) {
	h := newHandler()
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, verifyPost(expiredForm("/dashboard?a=1"), true), nextOK))
	require.Equal(t, 303, w.Code)
	require.Equal(t, "/dashboard?a=1", w.Result().Header.Get("Location"))
	require.Equal(t, "private, no-store", w.Result().Header.Get("Cache-Control"))
	c := triesCookie(t, w)
	require.NotNil(t, c)
	require.Equal(t, "1.0", c.Value)
	require.True(t, c.HttpOnly)
	require.True(t, c.Secure)
	require.Equal(t, http.SameSiteLaxMode, c.SameSite)
	require.Equal(t, 1800, c.MaxAge) // covers token TTL + slow solves
	require.Equal(t, "/", c.Path)
	for _, ck := range w.Result().Cookies() {
		require.NotEqual(t, CookieName, ck.Name, "no pass cookie on failure")
	}
}

func TestBrowserDetection(t *testing.T) {
	form := expiredForm("/x")
	// Accept text/html alone (no Sec-Fetch) is a browser.
	r := verifyPost(form, false)
	r.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	require.NoError(t, newHandler().ServeHTTP(w, r, nextOK))
	require.Equal(t, 303, w.Code)

	// Plain form POST without any Sec-Fetch headers (older browsers) is a browser.
	w = httptest.NewRecorder()
	require.NoError(t, newHandler().ServeHTTP(w, verifyPost(form, false), nextOK))
	require.Equal(t, 303, w.Code)
}

func TestNonBrowserVerifyFailureKeeps403(t *testing.T) {
	cases := map[string]func(r *http.Request){
		"fetch": func(r *http.Request) {
			r.Header.Set("Sec-Fetch-Mode", "cors")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("Accept", "*/*")
		},
		"json client": func(r *http.Request) {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json")
		},
		"no content type": func(r *http.Request) { r.Header.Del("Content-Type") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := verifyPost(expiredForm("/dashboard"), false)
			mutate(r)
			w := httptest.NewRecorder()
			require.NoError(t, newHandler().ServeHTTP(w, r, nextOK))
			require.Equal(t, 403, w.Code)
			require.Empty(t, w.Result().Header.Get("Location"))
			require.Nil(t, triesCookie(t, w))
		})
	}
}

// failingSolution returns a solution proven not to meet difficulty for tok.
func failingSolution(tok string, difficulty int) string {
	for i := 0; ; i++ {
		s := "bad" + strconv.Itoa(i)
		if leadingZeroBits(tok, s) < difficulty {
			return s
		}
	}
}

func TestBrowserVerifyBadSolutionUsesTokenReturnPath(t *testing.T) {
	// A still-valid token's ret wins over the form field.
	tok := IssueChallenge("h-secret", "203.0.113.5", "/from-token", timeNowPlus10())
	form := url.Values{"challenge": {tok}, "solution": {failingSolution(tok, 8)}, "ret": {"/from-form"}}
	r := verifyPost(form, true)
	w := httptest.NewRecorder()
	require.NoError(t, newHandler().ServeHTTP(w, r, nextOK))
	require.Equal(t, 303, w.Code)
	require.Equal(t, "/from-token", w.Result().Header.Get("Location"))
	vars := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any)
	require.Equal(t, "failed", vars["apx_challenge_outcome"])
	require.Equal(t, "1.0", triesCookie(t, w).Value)
	for _, ck := range w.Result().Cookies() {
		require.NotEqual(t, CookieName, ck.Name, "no pass cookie on failure")
	}
}

func TestBrowserVerifyRetFieldSanitized(t *testing.T) {
	for _, bad := range []string{"//evil.com", "/\\evil.com", "https://evil.com", "/\t/evil.com", "/\n/evil.com", "", "evil.com"} {
		form := url.Values{"challenge": {"garbage"}, "solution": {"1"}, "ret": {bad}}
		w := httptest.NewRecorder()
		require.NoError(t, newHandler().ServeHTTP(w, verifyPost(form, true), nextOK))
		require.Equal(t, 303, w.Code, bad)
		require.Equal(t, "/", w.Result().Header.Get("Location"), bad)
	}
}

func TestBrowserVerifyCounterIncrementsThenExplains(t *testing.T) {
	h := newHandler()
	var jar []*http.Cookie
	for i := 1; i <= 2; i++ {
		w := httptest.NewRecorder()
		require.NoError(t, h.ServeHTTP(w, verifyPost(expiredForm("/dashboard"), true, jar...), nextOK))
		require.Equal(t, 303, w.Code, "failure %d", i)
		c := triesCookie(t, w)
		require.NotNil(t, c)
		require.Equal(t, strconv.Itoa(i)+".0", c.Value)
		jar = []*http.Cookie{{Name: c.Name, Value: c.Value}}
	}

	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, verifyPost(expiredForm("/dashboard"), true, jar...), nextOK))
	require.Equal(t, 200, w.Code)
	require.Empty(t, w.Result().Header.Get("Location"))
	require.Equal(t, "text/html; charset=utf-8", w.Result().Header.Get("Content-Type"))
	require.Equal(t, "private, no-store", w.Result().Header.Get("Cache-Control"))
	body := w.Body.String()
	require.Contains(t, body, "We couldn't confirm your browser")
	require.Contains(t, body, `href="/dashboard"`)
	require.Equal(t, "3.0", triesCookie(t, w).Value)
	require.Contains(t, body, `data-reason="failed"`)

	// A malformed or huge counter can't wrap around into more redirects.
	for v, want := range map[string]int{
		"999999999999999999999.0": 303, // unparseable resets to 0
		"9223372036854775807.0":   200, // MaxInt64 + 1 must not wrap negative
		"garbage":                 303,
	} {
		w = httptest.NewRecorder()
		require.NoError(t, h.ServeHTTP(w, verifyPost(expiredForm("/dashboard"), true, &http.Cookie{Name: triesCookieName, Value: v}), nextOK))
		require.Equal(t, want, w.Code, v)
	}
}

func passForm(ret string) url.Values {
	tok := IssueChallenge("h-secret", "203.0.113.5", ret, timeNowPlus10())
	return url.Values{"challenge": {tok}, "solution": {SolvePoW(tok, 8)}, "ret": {ret}}
}

func TestVerifySuccessCountsAndKeepsCounter(t *testing.T) {
	h := newHandler()
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, verifyPost(passForm("/dashboard"), true, &http.Cookie{Name: triesCookieName, Value: "2.0"}), nextOK))
	require.Equal(t, 303, w.Code)
	require.Equal(t, "/dashboard", w.Result().Header.Get("Location"))
	c := triesCookie(t, w)
	require.NotNil(t, c)
	require.Equal(t, "2.1", c.Value) // two failures earlier don't block a pass
	require.Equal(t, 1800, c.MaxAge)
}

// A browser that passes but never sends the pass cookie back (cookies dropped,
// cross-site frame, /24 change between GET and POST) must not loop forever.
func TestVerifySuccessLoopEndsOnExplanationPage(t *testing.T) {
	h := newHandler()
	var jar []*http.Cookie
	for i := 1; i <= 2; i++ {
		w := httptest.NewRecorder()
		require.NoError(t, h.ServeHTTP(w, verifyPost(passForm("/dashboard"), true, jar...), nextOK))
		require.Equal(t, 303, w.Code, "pass %d", i)
		c := triesCookie(t, w)
		require.Equal(t, "0."+strconv.Itoa(i), c.Value)
		jar = []*http.Cookie{{Name: c.Name, Value: c.Value}}
	}
	r := verifyPost(passForm("/dashboard"), true, jar...)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Equal(t, 200, w.Code)
	require.Empty(t, w.Result().Header.Get("Location"))
	require.Equal(t, "private, no-store", w.Result().Header.Get("Cache-Control"))
	require.Contains(t, w.Body.String(), `data-reason="not_kept"`)
	require.Contains(t, w.Body.String(), `href="/dashboard"`)
	var names []string
	for _, ck := range w.Result().Cookies() {
		names = append(names, ck.Name)
	}
	require.Contains(t, names, CookieName, "the pass cookie is still issued")
	require.Equal(t, "0.3", triesCookie(t, w).Value)
	vars := r.Context().Value(caddyhttp.VarsCtxKey).(map[string]any)
	require.Equal(t, "passed", vars["apx_challenge_outcome"])
}

func TestValidPassCookieClearsCounter(t *testing.T) {
	h := newHandler()
	pass := &http.Cookie{Name: CookieName, Value: IssueCookie("h-secret", "203.0.113.5", timeNowPlus10())}

	r := browserReq("/dashboard")
	r.AddCookie(pass)
	r.AddCookie(&http.Cookie{Name: triesCookieName, Value: "1.2"})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Equal(t, "UPSTREAM", w.Body.String())
	c := triesCookie(t, w)
	require.NotNil(t, c)
	require.Equal(t, "", c.Value)
	require.Less(t, c.MaxAge, 0)

	// No counter on the request → no clearing header.
	r = browserReq("/dashboard")
	r.AddCookie(pass)
	w = httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Nil(t, triesCookie(t, w))

	// An invalid pass cookie doesn't clear it: the visitor is challenged again.
	r = browserReq("/dashboard")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "forged"})
	r.AddCookie(&http.Cookie{Name: triesCookieName, Value: "0.2"})
	w = httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Contains(t, w.Body.String(), "apx-challenge")
	require.Nil(t, triesCookie(t, w))
}

func TestChallengePageCarriesRet(t *testing.T) {
	w := httptest.NewRecorder()
	require.NoError(t, newHandler().ServeHTTP(w, browserReq("/dashboard?x=1"), nextOK))
	require.Contains(t, w.Body.String(), `name="ret" value="/dashboard?x=1"`)
	require.Contains(t, w.Body.String(), "var TIMEOUT_MS = 20000;")
}

func TestSafeReturn(t *testing.T) {
	require.Equal(t, "/dashboard", safeReturn("/dashboard"))
	require.Equal(t, "/a/b?x=1", safeReturn("/a/b?x=1"))
	require.Equal(t, "/", safeReturn("//evil.com"))
	require.Equal(t, "/", safeReturn("/\\evil.com")) // backslash bypass
	require.Equal(t, "/", safeReturn("https://evil.com"))
	require.Equal(t, "/", safeReturn("javascript:alert(1)"))
	require.Equal(t, "/", safeReturn(""))
	require.Equal(t, "/", safeReturn("/\t/evil.com")) // browsers strip tab → "//evil.com"
	require.Equal(t, "/", safeReturn("/\n/evil.com"))
	require.Equal(t, "/", safeReturn("/\x7f"))
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

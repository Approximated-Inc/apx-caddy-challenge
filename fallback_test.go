package apxchallenge

import (
	"bytes"
	"encoding/json"
	"image/gif"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

const (
	fbSecret = "h-secret"
	fbVP     = "/__apx_challenge/verify"
	fbIP     = "203.0.113.5"
	fbUA     = "Mozilla/5.0 (TestBrowser)"
)

// fbApp is fakeApp with a pass policy, the fallback config and persistent
// per-test stores.
type fbApp struct {
	fakeApp
	pol    PassPolicy
	fb     FallbackConfig
	replay *NonceLRU
	state  *FallbackState
}

func (a fbApp) PassPolicy() PassPolicy        { return a.pol }
func (a fbApp) Fallback() FallbackConfig      { return a.fb }
func (a fbApp) ReplayLRU() *NonceLRU          { return a.replay }
func (a fbApp) FallbackState() *FallbackState { return a.state }

func enabledFallback() FallbackConfig {
	return FallbackConfig{Enabled: true, PassTTL: 300 * time.Second, MaxPerHour: 3, MinDwell: 2 * time.Second}
}

func fbHandler(pol PassPolicy, fb FallbackConfig) (*ChallengeHandler, fbApp) {
	app := fbApp{fakeApp: fakeApp{sec: fbSecret, diff: 8, vp: fbVP}, pol: pol, fb: fb, replay: NewNonceLRU(1024), state: NewFallbackState(1024)}
	return &ChallengeHandler{app: app}, app
}

func fbGet(target, ip, ua string) *http.Request {
	r := httptest.NewRequest("GET", target, nil)
	r.RemoteAddr = ip + ":443"
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("User-Agent", ua)
	return withVars(r)
}

func fbPost(ip, ua, token, ret string, cookies ...*http.Cookie) *http.Request {
	form := url.Values{"mode": {"fallback"}, "fallback": {token}, "ret": {ret}}
	r := httptest.NewRequest("POST", fbVP, strings.NewReader(form.Encode()))
	r.RemoteAddr = ip + ":443"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("User-Agent", ua)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return withVars(r)
}

// fbCookie is a well-signed fallback cookie listing nonces.
func fbCookie(secret string, nonces ...string) *http.Cookie {
	body, _ := json.Marshal(nonces)
	return &http.Cookie{Name: fallbackCookieName, Value: encodeSigned(secret, fallbackCookieDomain, body)}
}

func respCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func outcomeOf(r *http.Request) any {
	return caddyhttp.GetVar(r.Context(), outcomeVarKey)
}

var (
	fbTokenRe = regexp.MustCompile(`name="fallback" value="([^"]+)"`)
	fbPixelRe = regexp.MustCompile(`url\("([^"]+)"\)`)
)

// issuedPage is one challenge response with its fallback parts.
type issuedPage struct {
	body, token, pixel string
	cookie             *http.Cookie
}

func issue(t *testing.T, h *ChallengeHandler, ip, ua, path string) issuedPage {
	t.Helper()
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, fbGet(path, ip, ua), nextOK))
	require.Equal(t, 200, w.Code)
	body := w.Body.String()
	tm, pm := fbTokenRe.FindStringSubmatch(body), fbPixelRe.FindStringSubmatch(body)
	require.NotNil(t, tm, "fallback token in page")
	require.NotNil(t, pm, "pixel URL in page CSS")
	c := respCookie(w, fallbackCookieName)
	require.NotNil(t, c, "fallback cookie set")
	return issuedPage{body: body, token: tm[1], pixel: pm[1], cookie: c}
}

func fetchPixel(t *testing.T, h *ChallengeHandler, pixel, ip string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", pixel, nil)
	r.RemoteAddr = ip + ":443"
	r.Header.Set("Accept", "image/avif,image/webp,*/*")
	r.Header.Set("Sec-Fetch-Dest", "image")
	r.Header.Set("User-Agent", fbUA)
	r = withVars(r)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	return w
}

// backdate re-mints the page's token with an issue time d ago (same nonce,
// prefix, UA and ret), standing in for the visitor's dwell.
func backdate(t *testing.T, app fbApp, token, ip, ua string, d time.Duration) string {
	t.Helper()
	p, err := verifyFallbackToken(fbSecret, app.pol, token, ip, ua, time.Now())
	require.NoError(t, err)
	return issueFallbackTokenNonce(fbSecret, app.pol, ip, ua, p.Ret, time.Now().Add(-d), p.Nonce)
}

func postFallback(t *testing.T, h *ChallengeHandler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	return w
}

// requireFailed asserts the browser failure path: a counted failure and a
// redirect to a fresh challenge, no pass cookie.
func requireFailed(t *testing.T, w *httptest.ResponseRecorder, r *http.Request, ret string) {
	t.Helper()
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, ret, w.Header().Get("Location"))
	require.Nil(t, respCookie(w, CookieName), "no pass cookie on failure")
	tc := respCookie(w, triesCookieName)
	require.NotNil(t, tc)
	rr := httptest.NewRequest("GET", "/", nil)
	rr.AddCookie(tc)
	require.Equal(t, 1, readTries(rr, fbSecret).Failed)
	require.Equal(t, "failed", outcomeOf(r))
}

// goldenFallbackView is a fixed fallback for the enabled-page golden.
var goldenFallbackView = fallbackView{
	Token:      "FALLBACK.TOKEN",
	PixelURL:   "/__apx_challenge/verify?apx_fallback_pixel=NONCE.1700000000.SIG",
	VerifyPath: "/__apx_challenge/verify",
	Ret:        "/a?b=<c>&d=\"e\"",
}

func TestFallbackGoldenPages(t *testing.T) {
	// Fallback off: byte-identical to master's page before the fallback (240c45a).
	off, err := os.ReadFile("testdata/challenge_page_fallback_disabled.golden.html")
	require.NoError(t, err)
	require.Equal(t, string(off), renderPage("TOKEN.SIG", 16, "/__apx_challenge/verify", "/a?b=<c>&d=\"e\"", 0))
	require.Equal(t, string(off), renderChallengePage("TOKEN.SIG", 16, "/__apx_challenge/verify", "/a?b=<c>&d=\"e\"", 0, nil))

	// Fallback on (the default): pinned so changes to it are deliberate.
	on, err := os.ReadFile("testdata/challenge_page_fallback_enabled.golden.html")
	require.NoError(t, err)
	fb := goldenFallbackView
	require.Equal(t, string(on), renderChallengePage("TOKEN.SIG", 16, "/__apx_challenge/verify", "/a?b=<c>&d=\"e\"", 0, &fb))
}

func TestFallbackIsOnByDefault(t *testing.T) {
	app := &ChallengeApp{SecretCfg: "s"}
	require.NoError(t, app.Provision(caddy.Context{}))
	require.Equal(t, FallbackConfig{Enabled: true, PassTTL: 600 * time.Second, MaxPerHour: 3, MinDwell: 2 * time.Second}, app.Fallback())

	h := &ChallengeHandler{app: app}
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, fbGet("/page?x=1", fbIP, fbUA), nextOK))
	require.Contains(t, w.Body.String(), "apx-fallback-form")
	require.Contains(t, w.Body.String(), fallbackPixelParam)
	require.NotNil(t, respCookie(w, fallbackCookieName))
}

func TestFallbackOptOutIsByteIdentical(t *testing.T) {
	app := &ChallengeApp{SecretCfg: "s", FallbackDisabledCfg: true}
	require.NoError(t, app.Provision(caddy.Context{}))
	require.False(t, app.Fallback().Enabled)

	h := &ChallengeHandler{app: app}
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, fbGet("/page?x=1", fbIP, fbUA), nextOK))
	body := w.Body.String()
	m := regexp.MustCompile(`name="challenge" value="([^"]+)"`).FindStringSubmatch(body)
	require.NotNil(t, m)
	require.Equal(t, renderPage(m[1], 16, defaultVerifyPath, "/page?x=1", 0), body)
	require.NotContains(t, body, "apx-fallback-form")
	require.NotContains(t, body, fallbackPixelParam)
	require.Len(t, w.Result().Cookies(), 0)

	// The opt-out also drops the pixel route and fallback mode.
	pr := httptest.NewRequest("GET", fallbackPixelURL("s", defaultVerifyPath, app.PassPolicy(), fbIP, fbUA, "Zm9vYmFyYmF6cXV4", time.Now().Add(time.Minute).Unix()), nil)
	pr.RemoteAddr = fbIP + ":443"
	pr.Header.Set("User-Agent", fbUA)
	pw := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(pw, withVars(pr), nextOK))
	require.NotEqual(t, "image/gif", pw.Header().Get("Content-Type"))
}

func TestFallbackDisabledHasNoPixelRouteOrPass(t *testing.T) {
	// Everything set but Enabled, so only the switch keeps it off.
	off := enabledFallback()
	off.Enabled = false
	h, app := fbHandler(DefaultPassPolicy(), off)
	nonce := "AAAAAAAAAAAAAAAA"
	exp := time.Now().Add(fallbackTokenTTL)
	w := fetchPixel(t, h, fallbackPixelURL(fbSecret, fbVP, app.pol, fbIP, "", nonce, exp.Unix()), fbIP)
	require.NotEqual(t, "image/gif", w.Header().Get("Content-Type"))
	require.False(t, app.state.Rendered.Has(nonce, time.Now()))

	// A well-formed fallback POST is not a fallback when off: no pass.
	app.state.Rendered.Add(nonce, exp, time.Now())
	tok := issueFallbackTokenNonce(fbSecret, app.pol, fbIP, fbUA, "/x", time.Now().Add(-time.Minute), nonce)
	// Sanity: the same POST passes when the switch is on.
	on := enabledFallback()
	hOn := &ChallengeHandler{app: fbApp{fakeApp: app.fakeApp, pol: app.pol, fb: on, replay: NewNonceLRU(16), state: renderedState(nonce)}}
	ckOn := fbCookie(fbSecret, nonce)
	require.NotNil(t, respCookie(postFallback(t, hOn, fbPost(fbIP, fbUA, tok, "/x", ckOn)), CookieName))

	ck := fbCookie(fbSecret, nonce)
	r := fbPost(fbIP, fbUA, tok, "/x", ck)
	w = postFallback(t, h, r)
	requireFailed(t, w, r, "/x")
}

func TestFallbackPageMarkupAndCookie(t *testing.T) {
	h, _ := fbHandler(DefaultPassPolicy(), enabledFallback())
	p := issue(t, h, fbIP, fbUA, "/page?q=1")

	require.Equal(t, "__Host-apx-challenge-fallback", p.cookie.Name)
	require.True(t, p.cookie.Secure)
	require.True(t, p.cookie.HttpOnly)
	require.Equal(t, http.SameSiteLaxMode, p.cookie.SameSite)
	require.Equal(t, "/", p.cookie.Path)
	require.Empty(t, p.cookie.Domain)
	require.Equal(t, 600, p.cookie.MaxAge)

	// The form sits in both the noscript block and the failure panel slot,
	// and the proof element the CSS styles is inside each form.
	ns := p.body[strings.Index(p.body, "<noscript>\n<div id=\"apx-noscript\">"):]
	ns = ns[:strings.Index(ns, "</noscript>")]
	require.Contains(t, ns, `<input type="hidden" name="mode" value="fallback">`)
	require.Contains(t, ns, `<span class="apx-fallback-proof" aria-hidden="true"></span>`)
	slot := p.body[strings.Index(p.body, `<div id="apx-fallback-slot">`):]
	require.Contains(t, slot[:strings.Index(slot, "</form>")], `class="apx-fallback-proof"`)
	require.Contains(t, p.body, `.apx-fallback-proof { display: block;`)
	require.True(t, strings.HasPrefix(p.pixel, fbVP+"?"+fallbackPixelParam+"="))
	require.Contains(t, p.body, `name="ret" value="/page?q=1"`)
}

func TestFallbackPassEndToEnd(t *testing.T) {
	fb := enabledFallback()
	fb.MinDwell = time.Millisecond
	h, _ := fbHandler(DefaultPassPolicy(), fb)
	p := issue(t, h, fbIP, fbUA, "/page?q=1")

	px := fetchPixel(t, h, p.pixel, fbIP)
	require.Equal(t, 200, px.Code)
	time.Sleep(5 * time.Millisecond)

	r := fbPost(fbIP, fbUA, p.token, "/ignored", p.cookie)
	w := postFallback(t, h, r)
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/page?q=1", w.Header().Get("Location"))
	require.Equal(t, "passed_fallback", outcomeOf(r))
	pc := respCookie(w, CookieName)
	require.NotNil(t, pc)
	require.Equal(t, 300, pc.MaxAge, "fallback pass TTL, not the pass policy's")
	cleared := respCookie(w, fallbackCookieName)
	require.NotNil(t, cleared)
	require.Equal(t, -1, cleared.MaxAge)

	// The pass cookie gets the visitor through.
	r2 := fbGet("/page?q=1", fbIP, fbUA)
	r2.AddCookie(pc)
	w2 := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w2, r2, nextOK))
	require.Equal(t, "UPSTREAM", w2.Body.String())
}

func TestFallbackPassCookieIsNonRolling(t *testing.T) {
	pol := PassPolicy{IdleTTL: time.Hour, MaxTTL: 24 * time.Hour, IPv4Prefix: 24, IPv6Prefix: 64}
	h, app := fbHandler(pol, enabledFallback())
	p := issue(t, h, fbIP, fbUA, "/page")
	fetchPixel(t, h, p.pixel, fbIP)
	w := postFallback(t, h, fbPost(fbIP, fbUA, backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/page", p.cookie))
	pc := respCookie(w, CookieName)
	require.NotNil(t, pc)
	require.Equal(t, 300, pc.MaxAge)

	got, ok := VerifyPassCookie(fbSecret, pol, pc.Value, fbIP, fbUA, time.Now())
	require.True(t, ok)
	require.True(t, got.IssuedAt.IsZero(), "no issued-at, so never renewed")

	// 300 s left is under half the 1 h idle TTL: a rolling cookie would renew
	// here. The fallback cookie must not.
	r := fbGet("/page", fbIP, fbUA)
	r.AddCookie(pc)
	w2 := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w2, r, nextOK))
	require.Equal(t, "UPSTREAM", w2.Body.String())
	require.Nil(t, respCookie(w2, CookieName), "fallback pass cookie must not roll")
}

func TestFallbackFailures(t *testing.T) {
	uaPol := DefaultPassPolicy()
	uaPol.BindUserAgent = true

	cases := []struct {
		name string
		pol  PassPolicy
		fb   func(*FallbackConfig)
		// run issues and prepares, then returns the POST.
		run func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request
	}{
		{"missing cookie", DefaultPassPolicy(), nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			return fbPost(fbIP, fbUA, backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/r")
		}},
		{"cookie for another nonce", DefaultPassPolicy(), nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			other := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			return fbPost(fbIP, fbUA, backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/r", other.cookie)
		}},
		{"forged cookie", DefaultPassPolicy(), nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			tp, _ := verifyFallbackToken(fbSecret, app.pol, p.token, fbIP, fbUA, time.Now())
			forged := fbCookie("other-secret", tp.Nonce)
			return fbPost(fbIP, fbUA, backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/r", forged)
		}},
		{"pixel not rendered", DefaultPassPolicy(), nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			return fbPost(fbIP, fbUA, backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/r", p.cookie)
		}},
		{"too fast", DefaultPassPolicy(), nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			return fbPost(fbIP, fbUA, backdate(t, app, p.token, fbIP, fbUA, 1500*time.Millisecond), "/r", p.cookie)
		}},
		{"dwell is configurable", DefaultPassPolicy(), func(fb *FallbackConfig) { fb.MinDwell = 10 * time.Second }, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			return fbPost(fbIP, fbUA, backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/r", p.cookie)
		}},
		{"replayed nonce", DefaultPassPolicy(), nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			tok := backdate(t, app, p.token, fbIP, fbUA, 3*time.Second)
			w := postFallback(t, h, fbPost(fbIP, fbUA, tok, "/r", p.cookie))
			require.NotNil(t, respCookie(w, CookieName), "first use passes")
			return fbPost(fbIP, fbUA, tok, "/r", p.cookie)
		}},
		{"other prefix", DefaultPassPolicy(), nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			return fbPost("198.51.100.7", fbUA, backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/r", p.cookie)
		}},
		{"other UA under UA binding", uaPol, nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			return fbPost(fbIP, "curl/8.0", backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/r", p.cookie)
		}},
		{"expired token", DefaultPassPolicy(), nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			return fbPost(fbIP, fbUA, backdate(t, app, p.token, fbIP, fbUA, fallbackTokenTTL+2*time.Second), "/r", p.cookie)
		}},
		{"fallback payload signed under another label", DefaultPassPolicy(), nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			// Cookie, render and dwell all hold; only the signature label is wrong.
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			tp, err := verifyFallbackToken(fbSecret, app.pol, p.token, fbIP, fbUA, time.Now())
			require.NoError(t, err)
			tp.Iat = time.Now().Add(-3 * time.Second).UnixMilli()
			body, _ := json.Marshal(tp)
			good := encodeSigned(fbSecret, fallbackDomain, body)
			ok := postFallback(t, &ChallengeHandler{app: fbApp{fakeApp: app.fakeApp, pol: app.pol, fb: app.fb, replay: app.replay, state: renderedState(tp.Nonce)}}, fbPost(fbIP, fbUA, good, "/r", p.cookie))
			require.NotNil(t, respCookie(ok, CookieName), "control: the same body under the fallback label passes")
			return fbPost(fbIP, fbUA, encodeSigned(fbSecret, challengeDomain, body), "/r", p.cookie)
		}},
		{"rate limit", DefaultPassPolicy(), func(fb *FallbackConfig) { fb.MaxPerHour = 2 }, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			// Two passes from the /24 (different addresses in it), then the third fails.
			for _, ip := range []string{"203.0.113.9", "203.0.113.10"} {
				p := issue(t, h, ip, fbUA, "/r")
				fetchPixel(t, h, p.pixel, ip)
				w := postFallback(t, h, fbPost(ip, fbUA, backdate(t, app, p.token, ip, fbUA, 3*time.Second), "/r", p.cookie))
				require.NotNil(t, respCookie(w, CookieName), "under the limit passes")
			}
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			return fbPost(fbIP, fbUA, backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/r", p.cookie)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fb := enabledFallback()
			if tc.fb != nil {
				tc.fb(&fb)
			}
			h, app := fbHandler(tc.pol, fb)
			r := tc.run(t, h, app)
			w := postFallback(t, h, r)
			requireFailed(t, w, r, "/r")
		})
	}
}

// renderedState is a fresh state with nonce rendered, so a control POST
// doesn't spend the nonce in the state under test.
func renderedState(nonce string) *FallbackState {
	st := NewFallbackState(16)
	st.Rendered.Add(nonce, time.Now().Add(fallbackTokenTTL), time.Now())
	return st
}

func TestFallbackNonBrowserPostGets403(t *testing.T) {
	h, _ := fbHandler(DefaultPassPolicy(), enabledFallback())
	p := issue(t, h, fbIP, fbUA, "/r")
	form := url.Values{"mode": {"fallback"}, "fallback": {p.token}, "ret": {"/r"}}
	r := httptest.NewRequest("POST", fbVP, strings.NewReader(form.Encode()))
	r.RemoteAddr = fbIP + ":443"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Mode", "cors")
	r.AddCookie(p.cookie)
	r = withVars(r)
	w := postFallback(t, h, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Equal(t, "failed", outcomeOf(r))
}

func TestFallbackUnboundUAStillPasses(t *testing.T) {
	h, app := fbHandler(DefaultPassPolicy(), enabledFallback())
	p := issue(t, h, fbIP, fbUA, "/r")
	fetchPixel(t, h, p.pixel, fbIP)
	w := postFallback(t, h, fbPost(fbIP, "Other/1.0", backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/r", p.cookie))
	require.NotNil(t, respCookie(w, CookieName))
}

func TestFallbackPixelEndpoint(t *testing.T) {
	uaPol := DefaultPassPolicy()
	uaPol.BindUserAgent = true
	h, app := fbHandler(uaPol, enabledFallback())
	nonce := "Zm9vYmFyYmF6cXV4"
	now := time.Now()
	exp := now.Add(fallbackTokenTTL).Unix()
	good := fallbackPixelURL(fbSecret, fbVP, uaPol, fbIP, fbUA, nonce, exp)

	get := func(u, ip, ua, method string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, u, nil)
		r.RemoteAddr = ip + ":443"
		r.Header.Set("Accept", "image/avif,image/webp,*/*")
		r.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		require.NoError(t, h.ServeHTTP(w, withVars(r), nextOK))
		return w
	}

	w := get(good, "203.0.113.200", fbUA, "GET") // same /24
	require.Equal(t, 200, w.Code)
	require.Equal(t, "image/gif", w.Header().Get("Content-Type"))
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	img, err := gif.Decode(bytes.NewReader(w.Body.Bytes()))
	require.NoError(t, err)
	require.Equal(t, 1, img.Bounds().Dx())
	require.Equal(t, 1, img.Bounds().Dy())
	require.True(t, app.state.Rendered.Has(nonce, now))
	// The render record lives as long as the token, no longer.
	require.False(t, app.state.Rendered.Has(nonce, time.Unix(exp+1, 0)))

	param := fbVP + "?" + fallbackPixelParam + "="
	e := strconv.FormatInt(exp, 10)
	past := now.Add(-time.Second).Unix()
	bad := []struct{ name, url, ip, ua string }{
		{"bad signature", param + nonce + "." + e + ".AAAA", fbIP, fbUA},
		{"other secret", fallbackPixelURL("other-secret", fbVP, uaPol, fbIP, fbUA, nonce, exp), fbIP, fbUA},
		{"expired", fallbackPixelURL(fbSecret, fbVP, uaPol, fbIP, fbUA, nonce, past), fbIP, fbUA},
		{"expiry edited", param + nonce + "." + strconv.FormatInt(exp+3600, 10) + "." + good[strings.LastIndexByte(good, '.')+1:], fbIP, fbUA},
		{"other prefix", good, "198.51.100.7", fbUA},
		{"other UA under UA binding", good, fbIP, "curl/8.0"},
		{"empty", param, fbIP, fbUA},
		{"nonce only", param + nonce + "." + sign(fbSecret, fallbackPixelDomain, []byte(nonce)), fbIP, fbUA},
		{"wrong nonce length", fallbackPixelURL(fbSecret, fbVP, uaPol, fbIP, fbUA, "short", exp), fbIP, fbUA},
		{"another domain's signature", param + nonce + "." + e + "." + sign(fbSecret, fallbackCookieDomain, []byte(nonce+"|"+e+"|203.0.113.0/24|"+uaHash(fbUA))), fbIP, fbUA},
	}
	for _, tc := range bad {
		app.state = NewFallbackState(16)
		h.app = app
		w := get(tc.url, tc.ip, tc.ua, "GET")
		require.Equal(t, http.StatusNotFound, w.Code, tc.name)
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"), tc.name)
		require.Empty(t, w.Body.String(), tc.name)
		require.Equal(t, 0, app.state.Rendered.ll.Len(), tc.name)
	}

	// HEAD records too but sends no body.
	app.state = NewFallbackState(16)
	h.app = app
	w = get(good, fbIP, fbUA, "HEAD")
	require.Equal(t, 200, w.Code)
	require.Empty(t, w.Body.Bytes())
	require.True(t, app.state.Rendered.Has(nonce, now))
}

func TestFallbackRenderEscapes(t *testing.T) {
	fb := fallbackView{
		Token:      `tok"<x>`,
		PixelURL:   `/v"</style><script>alert(1)</script>?apx_fallback_pixel=n.s` + "\n\\",
		VerifyPath: `/v"><script>`,
		Ret:        `/p?a="b"&c=<d>{{JS}}`,
	}
	body := renderChallengePage("T", 8, "/v", fb.Ret, 0, &fb)
	require.NotContains(t, body, `</style><script>alert`)
	require.NotContains(t, body, `tok"<x>`)
	require.NotContains(t, body, `/v"><script>`)
	require.Contains(t, body, `value="tok&#34;&lt;x&gt;"`)
	require.Contains(t, body, `url("/v\22 \3c /style\3e \3c script\3e alert\28 1\29 \3c /script\3e ?apx_fallback_pixel=n.s\a \5c ")`)
	// Substituted values are not rescanned for placeholders.
	require.Contains(t, body, `{{JS}}`)
	require.Equal(t, 1, strings.Count(body, powJS))
}

func TestFallbackConfigValidation(t *testing.T) {
	fb, err := buildFallbackConfig(false, 0, 0, 0, 600*time.Second)
	require.NoError(t, err)
	require.Equal(t, FallbackConfig{PassTTL: 600 * time.Second, MaxPerHour: 3, MinDwell: 2 * time.Second}, fb)

	// Never longer than a solved cookie: the default clamps, an explicit value errors.
	fb, err = buildFallbackConfig(true, 0, 0, 0, 300*time.Second)
	require.NoError(t, err)
	require.Equal(t, 300*time.Second, fb.PassTTL)
	_, err = buildFallbackConfig(true, 301, 0, 0, 300*time.Second)
	require.ErrorContains(t, err, "must not exceed the pass idle TTL")
	fb, err = buildFallbackConfig(true, 300, 0, 0, 300*time.Second)
	require.NoError(t, err)
	require.Equal(t, 300*time.Second, fb.PassTTL)
	clamped := &ChallengeApp{SecretCfg: "s", PassIdleTTLSecondsCfg: 120}
	require.NoError(t, clamped.Provision(caddy.Context{}))
	require.Equal(t, 120*time.Second, clamped.Fallback().PassTTL)
	require.Error(t, (&ChallengeApp{SecretCfg: "s", PassIdleTTLSecondsCfg: 120, FallbackPassTTLSecondsCfg: 121}).Provision(caddy.Context{}))

	app := &ChallengeApp{SecretCfg: "s", FallbackPassTTLSecondsCfg: 120, FallbackMaxPerHourCfg: 5, FallbackMinDwellSecondsCfg: 4}
	require.NoError(t, app.Provision(caddy.Context{}))
	require.Equal(t, FallbackConfig{Enabled: true, PassTTL: 120 * time.Second, MaxPerHour: 5, MinDwell: 4 * time.Second}, app.Fallback())
	require.Same(t, processFallbackState, app.FallbackState())

	for _, bad := range []ChallengeApp{
		{SecretCfg: "s", FallbackPassTTLSecondsCfg: -1},
		{SecretCfg: "s", FallbackPassTTLSecondsCfg: 59},
		{SecretCfg: "s", FallbackPassTTLSecondsCfg: 86401},
		{SecretCfg: "s", FallbackMaxPerHourCfg: -1},
		{SecretCfg: "s", FallbackMaxPerHourCfg: 1001},
		{SecretCfg: "s", FallbackMinDwellSecondsCfg: -1},
		{SecretCfg: "s", FallbackMinDwellSecondsCfg: 61},
	} {
		require.Error(t, bad.Provision(caddy.Context{}), "%+v", bad)
	}
	for _, ok := range []ChallengeApp{
		{SecretCfg: "s", FallbackPassTTLSecondsCfg: 60, FallbackMaxPerHourCfg: 1, FallbackMinDwellSecondsCfg: 1},
		{SecretCfg: "s", PassIdleTTLSecondsCfg: 86400, FallbackPassTTLSecondsCfg: 86400, FallbackMaxPerHourCfg: 1000, FallbackMinDwellSecondsCfg: 60},
	} {
		require.NoError(t, ok.Provision(caddy.Context{}))
	}
}

func TestFallbackLimiter(t *testing.T) {
	l := NewFallbackLimiter(2)
	now := time.Now()
	require.True(t, l.Allow("a", 2, now))
	require.True(t, l.Allow("a", 2, now.Add(time.Minute)))
	require.False(t, l.Allow("a", 2, now.Add(2*time.Minute)))
	// The first pass ages out of the hour.
	require.True(t, l.Allow("a", 2, now.Add(time.Hour+time.Second)))
	require.False(t, l.Allow("a", 2, now.Add(time.Hour+2*time.Second)))

	// Bounded: a third key evicts the least recently used.
	require.True(t, l.Allow("b", 1, now))
	require.True(t, l.Allow("c", 1, now))
	require.Equal(t, 2, l.ll.Len())
	require.NotContains(t, l.m, "a")
}

func TestFallbackNeverTouchesSharedReplayLRU(t *testing.T) {
	fb := enabledFallback()
	fb.MaxPerHour = 1
	h, app := fbHandler(DefaultPassPolicy(), fb)
	pass := func(ip string) (*httptest.ResponseRecorder, string) {
		p := issue(t, h, ip, fbUA, "/r")
		fetchPixel(t, h, p.pixel, ip)
		tok := backdate(t, app, p.token, ip, fbUA, 3*time.Second)
		tp, _ := verifyFallbackToken(fbSecret, app.pol, tok, ip, fbUA, time.Now())
		return postFallback(t, h, fbPost(ip, fbUA, tok, "/r", p.cookie)), tp.Nonce
	}
	w, first := pass(fbIP)
	require.NotNil(t, respCookie(w, CookieName))
	require.True(t, app.state.Spent.Has(first, time.Now()))

	// Over the budget: fails, and the nonce is not spent.
	w, second := pass("203.0.113.6")
	require.Nil(t, respCookie(w, CookieName))
	require.False(t, app.state.Spent.Has(second, time.Now()), "a rate-denied attempt must not spend its nonce")

	require.Equal(t, 0, app.replay.ll.Len(), "fallback must not write the shared replay LRU")
}

// faviconReq is an old browser's subresource request: Accept */*, no Sec-Fetch.
func faviconReq(ip string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest("GET", "/favicon.ico", nil)
	r.RemoteAddr = ip + ":443"
	r.Header.Set("Accept", "*/*")
	r.Header.Set("User-Agent", fbUA)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return withVars(r)
}

func TestFallbackFaviconAfterPageDoesNotStrandIt(t *testing.T) {
	h, app := fbHandler(DefaultPassPolicy(), enabledFallback())
	p := issue(t, h, fbIP, fbUA, "/r")

	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, faviconReq(fbIP, p.cookie), nextOK))
	require.Equal(t, 200, w.Code, "still a challenge page")
	require.Nil(t, respCookie(w, fallbackCookieName), "a */* subresource must not touch the fallback cookie")
	require.NotContains(t, w.Body.String(), "apx-fallback-form")

	fetchPixel(t, h, p.pixel, fbIP)
	w = postFallback(t, h, fbPost(fbIP, fbUA, backdate(t, app, p.token, fbIP, fbUA, 3*time.Second), "/r", p.cookie))
	require.NotNil(t, respCookie(w, CookieName))
}

func TestFallbackDocumentDetection(t *testing.T) {
	for _, tc := range []struct {
		accept, dest string
		want         bool
	}{
		{"text/html,application/xhtml+xml", "", true},
		{"text/html, application/xhtml+xml, image/jxr, */*", "", true}, // IE11 navigation
		{"*/*", "document", true},
		{"*/*", "", false},
		{"image/avif,image/webp,*/*", "image", false},
		{"", "", false},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Accept", tc.accept)
		if tc.dest != "" {
			r.Header.Set("Sec-Fetch-Dest", tc.dest)
		}
		require.Equal(t, tc.want, isLikelyDocument(r), "%+v", tc)
	}
}

func TestFallbackTwoTabs(t *testing.T) {
	h, app := fbHandler(DefaultPassPolicy(), enabledFallback())
	a := issue(t, h, fbIP, fbUA, "/a")
	// Tab B loads while the browser holds tab A's cookie.
	rb := fbGet("/b", fbIP, fbUA)
	rb.AddCookie(a.cookie)
	wb := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(wb, rb, nextOK))
	bTok := fbTokenRe.FindStringSubmatch(wb.Body.String())[1]
	bPixel := fbPixelRe.FindStringSubmatch(wb.Body.String())[1]
	jar := respCookie(wb, fallbackCookieName)
	require.NotNil(t, jar)

	fetchPixel(t, h, a.pixel, fbIP)
	fetchPixel(t, h, bPixel, fbIP)

	// Tab A continues with the latest cookie, then tab B.
	wa := postFallback(t, h, fbPost(fbIP, fbUA, backdate(t, app, a.token, fbIP, fbUA, 3*time.Second), "/a", jar))
	require.NotNil(t, respCookie(wa, CookieName), "the older tab passes")
	jar = respCookie(wa, fallbackCookieName)
	require.NotNil(t, jar)
	require.Greater(t, jar.MaxAge, 0, "the other tab's nonce is kept")
	wb2 := postFallback(t, h, fbPost(fbIP, fbUA, backdate(t, app, bTok, fbIP, fbUA, 3*time.Second), "/b", jar))
	require.NotNil(t, respCookie(wb2, CookieName), "the newer tab passes")
	require.Equal(t, -1, respCookie(wb2, fallbackCookieName).MaxAge, "cookie cleared once empty")
}

func TestFallbackCookieKeepsRecentNonces(t *testing.T) {
	var ns []string
	for _, n := range []string{"a", "b", "c", "d", "e", "c"} {
		ns = withNonce(ns, n)
	}
	require.Equal(t, []string{"c", "e", "d", "b"}, ns)
	require.Equal(t, []string{"c", "d", "b"}, withoutNonce(ns, "e"))

	// A cookie listing more than the cap is read only up to the cap.
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(fbCookie(fbSecret, "1", "2", "3", "4", "5"))
	require.Equal(t, []string{"1", "2", "3", "4"}, readFallbackNonces(r, fbSecret))
	require.False(t, fallbackCookieMatches(r, fbSecret, "5"))
	require.True(t, fallbackCookieMatches(r, fbSecret, "4"))
}

func TestExpiringSet(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := NewExpiringSet(3)
	s.Add("a", now.Add(10*time.Second), now)
	require.True(t, s.Has("a", now.Add(10*time.Second)))
	require.False(t, s.Has("a", now.Add(11*time.Second)), "expired")
	require.False(t, s.Has("x", now))

	require.True(t, s.AddIfAbsent("b", now.Add(time.Minute), now))
	require.False(t, s.AddIfAbsent("b", now.Add(time.Minute), now), "live record")
	// An expired record can be re-added.
	require.True(t, s.AddIfAbsent("a", now.Add(time.Minute), now.Add(20*time.Second)))

	// Expired records are dropped from the old end on add.
	s2 := NewExpiringSet(10)
	s2.Add("old", now, now)
	s2.Add("new", now.Add(time.Hour), now.Add(time.Minute))
	require.Equal(t, 1, s2.ll.Len())

	// Bounded: past max, the least recently added goes.
	s3 := NewExpiringSet(2)
	for _, k := range []string{"p", "q", "r"} {
		s3.Add(k, now.Add(time.Hour), now)
	}
	require.Equal(t, 2, s3.ll.Len())
	require.False(t, s3.Has("p", now))
	require.True(t, s3.Has("r", now))
}

func TestFallbackReplayDoesNotUseBudget(t *testing.T) {
	fb := enabledFallback()
	fb.MaxPerHour = 2
	h, app := fbHandler(DefaultPassPolicy(), fb)
	p := issue(t, h, fbIP, fbUA, "/r")
	fetchPixel(t, h, p.pixel, fbIP)
	tok := backdate(t, app, p.token, fbIP, fbUA, 3*time.Second)
	require.NotNil(t, respCookie(postFallback(t, h, fbPost(fbIP, fbUA, tok, "/r", p.cookie)), CookieName))
	require.Nil(t, respCookie(postFallback(t, h, fbPost(fbIP, fbUA, tok, "/r", p.cookie)), CookieName), "replay fails")

	// The replay used no budget, so a second real pass from the prefix fits.
	q := issue(t, h, fbIP, fbUA, "/r")
	fetchPixel(t, h, q.pixel, fbIP)
	w := postFallback(t, h, fbPost(fbIP, fbUA, backdate(t, app, q.token, fbIP, fbUA, 3*time.Second), "/r", q.cookie))
	require.NotNil(t, respCookie(w, CookieName))
}

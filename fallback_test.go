package apxchallenge

import (
	"bytes"
	"image/gif"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
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

func TestFallbackDefaultPageMatchesGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/challenge_page_default.golden.html")
	require.NoError(t, err)
	require.Equal(t, string(want), renderPage("TOKEN.SIG", 16, "/__apx_challenge/verify", "/a?b=<c>&d=\"e\"", 0))
	require.Equal(t, string(want), renderChallengePage("TOKEN.SIG", 16, "/__apx_challenge/verify", "/a?b=<c>&d=\"e\"", 0, nil))
}

func TestFallbackUnchangedConfigIsOffAndByteIdentical(t *testing.T) {
	app := &ChallengeApp{SecretCfg: "s"}
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
}

func TestFallbackDisabledHasNoPixelRouteOrPass(t *testing.T) {
	// Everything set but Enabled, so only the switch keeps it off.
	off := enabledFallback()
	off.Enabled = false
	h, app := fbHandler(DefaultPassPolicy(), off)
	nonce := "AAAAAAAAAAAAAAAA"
	w := fetchPixel(t, h, fallbackPixelURL(fbSecret, fbVP, nonce), fbIP)
	require.NotEqual(t, "image/gif", w.Header().Get("Content-Type"))
	require.False(t, app.state.Rendered.Contains(fallbackRenderedKeyPrefix+nonce))

	// A well-formed fallback POST is not a fallback when off: no pass.
	app.state.Rendered.Seen(fallbackRenderedKeyPrefix + nonce)
	tok := issueFallbackTokenNonce(fbSecret, app.pol, fbIP, fbUA, "/x", time.Now().Add(-time.Minute), nonce)
	// Sanity: the same POST passes when the switch is on.
	on := enabledFallback()
	hOn := &ChallengeHandler{app: fbApp{fakeApp: app.fakeApp, pol: app.pol, fb: on, replay: NewNonceLRU(16), state: app.state}}
	ckOn := &http.Cookie{Name: fallbackCookieName, Value: encodeSigned(fbSecret, fallbackCookieDomain, []byte(nonce))}
	require.NotNil(t, respCookie(postFallback(t, hOn, fbPost(fbIP, fbUA, tok, "/x", ckOn)), CookieName))

	ck := &http.Cookie{Name: fallbackCookieName, Value: encodeSigned(fbSecret, fallbackCookieDomain, []byte(nonce))}
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
			forged := &http.Cookie{Name: fallbackCookieName, Value: encodeSigned("other-secret", fallbackCookieDomain, []byte(tp.Nonce))}
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
		{"challenge token in the fallback field", DefaultPassPolicy(), nil, func(t *testing.T, h *ChallengeHandler, app fbApp) *http.Request {
			p := issue(t, h, fbIP, fbUA, "/r")
			fetchPixel(t, h, p.pixel, fbIP)
			m := regexp.MustCompile(`name="challenge" value="([^"]+)"`).FindStringSubmatch(p.body)
			return fbPost(fbIP, fbUA, m[1], "/r", p.cookie)
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
	h, app := fbHandler(DefaultPassPolicy(), enabledFallback())
	nonce := "Zm9vYmFyYmF6cXV4"
	good := fallbackPixelURL(fbSecret, fbVP, nonce)

	w := fetchPixel(t, h, good, fbIP)
	require.Equal(t, 200, w.Code)
	require.Equal(t, "image/gif", w.Header().Get("Content-Type"))
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	img, err := gif.Decode(bytes.NewReader(w.Body.Bytes()))
	require.NoError(t, err)
	require.Equal(t, 1, img.Bounds().Dx())
	require.Equal(t, 1, img.Bounds().Dy())
	require.True(t, app.state.Rendered.Contains(fallbackRenderedKeyPrefix+nonce))

	bad := []string{
		fbVP + "?" + fallbackPixelParam + "=" + nonce + ".AAAA",                                                   // bad signature
		fallbackPixelURL("other-secret", fbVP, "b3RoZXJub25jZXh4"),                                                // other secret
		fbVP + "?" + fallbackPixelParam + "=",                                                                     // empty
		fbVP + "?" + fallbackPixelParam + "=" + "short." + sign(fbSecret, fallbackPixelDomain, []byte("short")),   // wrong nonce length
		fbVP + "?" + fallbackPixelParam + "=" + nonce + "." + sign(fbSecret, fallbackCookieDomain, []byte(nonce)), // another domain's signature
	}
	for _, u := range bad {
		app.state = NewFallbackState(16)
		h.app = app
		w := fetchPixel(t, h, u, fbIP)
		require.Equal(t, http.StatusNotFound, w.Code, u)
		require.Equal(t, "no-store", w.Header().Get("Cache-Control"), u)
		require.Empty(t, w.Body.String(), u)
		require.Equal(t, 0, app.state.Rendered.ll.Len(), u)
	}

	// HEAD records too but sends no body.
	app.state = NewFallbackState(16)
	h.app = app
	r := httptest.NewRequest("HEAD", good, nil)
	r.RemoteAddr = fbIP + ":443"
	w = httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, withVars(r), nextOK))
	require.Equal(t, 200, w.Code)
	require.Empty(t, w.Body.Bytes())
	require.True(t, app.state.Rendered.Contains(fallbackRenderedKeyPrefix+nonce))
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
	fb, err := buildFallbackConfig(false, 0, 0, 0)
	require.NoError(t, err)
	require.Equal(t, FallbackConfig{PassTTL: 600 * time.Second, MaxPerHour: 3, MinDwell: 2 * time.Second}, fb)

	app := &ChallengeApp{SecretCfg: "s", FallbackEnabledCfg: true, FallbackPassTTLSecondsCfg: 120, FallbackMaxPerHourCfg: 5, FallbackMinDwellSecondsCfg: 4}
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
		{SecretCfg: "s", FallbackPassTTLSecondsCfg: 86400, FallbackMaxPerHourCfg: 1000, FallbackMinDwellSecondsCfg: 60},
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

func TestNonceLRUContainsDoesNotRecord(t *testing.T) {
	l := NewNonceLRU(4)
	require.False(t, l.Contains("x"))
	require.False(t, l.Contains("x"))
	require.False(t, l.Seen("x"))
	require.True(t, l.Contains("x"))
}

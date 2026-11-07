package apxchallenge

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

// outcomeAndReason returns the two request vars the stats recorder reads.
func outcomeAndReason(r *http.Request) (any, any) {
	return caddyhttp.GetVar(r.Context(), outcomeVarKey), caddyhttp.GetVar(r.Context(), reasonVarKey)
}

func serveReq(t *testing.T, h *ChallengeHandler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	return w
}

func TestIssuedReasonSeparatesDocumentsFromOtherRequests(t *testing.T) {
	cases := []struct {
		name, method string
		hdr          map[string]string
		reason       string
	}{
		{"html navigation", "GET", map[string]string{"Accept": "text/html,application/xhtml+xml"}, reasonDocument},
		{"sec-fetch document", "GET", map[string]string{"Accept": "*/*", "Sec-Fetch-Dest": "document"}, reasonDocument},
		{"form post navigation", "POST", map[string]string{"Accept": "text/html"}, reasonDocument},
		{"HEAD never renders", "HEAD", map[string]string{"Accept": "text/html"}, reasonOther},
		{"accept anything", "GET", map[string]string{"Accept": "*/*"}, reasonOther},
		{"no accept header", "GET", map[string]string{}, reasonOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/page", nil)
			r.RemoteAddr = "203.0.113.5:443"
			for k, v := range tc.hdr {
				r.Header.Set(k, v)
			}
			r = withVars(r)
			w := serveReq(t, newHandler(), r)
			require.Equal(t, http.StatusOK, w.Code)
			outcome, reason := outcomeAndReason(r)
			// The outcome var keeps its value: the response guard route matches "issued".
			require.Equal(t, "issued", outcome)
			require.Equal(t, tc.reason, reason)
		})
	}
}

func TestNotShownReasons(t *testing.T) {
	api := httptest.NewRequest("GET", "/api/x", nil)
	api.RemoteAddr = "203.0.113.5:443"
	api.Header.Set("Accept", "application/json")
	api = withVars(api)
	require.Equal(t, http.StatusTooManyRequests, serveReq(t, newHandler(), api).Code)
	outcome, reason := outcomeAndReason(api)
	require.Equal(t, "failed", outcome)
	require.Equal(t, reasonAPI, reason)

	ws := browserReq("/ws")
	ws.Header.Set("Upgrade", "websocket")
	require.Equal(t, http.StatusServiceUnavailable, serveReq(t, newHandler(), ws).Code)
	outcome, reason = outcomeAndReason(ws)
	require.Equal(t, "failed", outcome)
	require.Equal(t, reasonStream, reason)
}

func verifyReq(form url.Values, ip, ua string) *http.Request {
	r := httptest.NewRequest("POST", "/__apx_challenge/verify", strings.NewReader(form.Encode()))
	r.RemoteAddr = ip + ":443"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Sec-Fetch-Mode", "cors") // a script: failures get the bare 403
	return withVars(r)
}

func TestVerifyFailureReasons(t *testing.T) {
	const ip, ua = "203.0.113.5", "UA-1"
	uaPol := DefaultPassPolicy()
	uaPol.BindUserAgent = true
	soon := time.Now().Add(challengeTokenTTL)
	solved := func(tok string) url.Values {
		return url.Values{"challenge": {tok}, "solution": {SolvePoW(tok, 8)}}
	}
	tok := IssueChallenge("h-secret", ip, "/", soon)

	cases := []struct {
		name   string
		h      *ChallengeHandler
		form   url.Values
		ip, ua string
		reason string
	}{
		{"no token", newHandler(), url.Values{"solution": {"1"}}, ip, ua, reasonToken},
		{"garbage token", newHandler(), url.Values{"challenge": {"garbage"}, "solution": {"1"}}, ip, ua, reasonToken},
		{"token under another secret", newHandler(), solved(IssueChallenge("other-secret", ip, "/", soon)), ip, ua, reasonToken},
		{"expired token", newHandler(), solved(IssueChallenge("h-secret", ip, "/", time.Now().Add(-time.Second))), ip, ua, reasonExpired},
		{"token for another prefix", newHandler(), solved(IssueChallenge("h-secret", "198.51.100.7", "/", soon)), ip, ua, reasonBinding},
		{"token for another UA", policyHandler(uaPol), solved(IssuePassChallenge("h-secret", uaPol, ip, "UA-2", "/", soon)), ip, ua, reasonBinding},
		{"wrong proof", newHandler(), url.Values{"challenge": {tok}, "solution": {failingSolution(tok, 8)}}, ip, ua, reasonProof},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := verifyReq(tc.form, tc.ip, tc.ua)
			require.Equal(t, http.StatusForbidden, serveReq(t, tc.h, r).Code)
			outcome, reason := outcomeAndReason(r)
			require.Equal(t, "failed", outcome)
			require.Equal(t, tc.reason, reason)
		})
	}
}

func TestReplayedSolveReasonIsReplay(t *testing.T) {
	pol := DefaultPassPolicy()
	pol.IPv4Prefix = 32
	h := policyHandler(pol)
	tok := IssuePassChallenge("h-secret", pol, "203.0.113.5", "UA", "/dest", time.Now().Add(challengeTokenTTL))
	form := url.Values{"challenge": {tok}, "solution": {SolvePoW(tok, 8)}}

	first := verifyReq(form, "203.0.113.5", "UA")
	require.Equal(t, http.StatusSeeOther, serveReq(t, h, first).Code)
	outcome, reason := outcomeAndReason(first)
	require.Equal(t, "passed", outcome)
	require.Nil(t, reason, "a pass records no reason")

	again := verifyReq(form, "203.0.113.5", "UA")
	require.Equal(t, http.StatusForbidden, serveReq(t, h, again).Code)
	outcome, reason = outcomeAndReason(again)
	require.Equal(t, "failed", outcome)
	require.Equal(t, reasonReplay, reason)
}

func TestPassedRecentlyRecordsNoReason(t *testing.T) {
	r := browserReq("/dashboard")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: IssueCookie("h-secret", "203.0.113.5", timeNowPlus10())})
	require.Equal(t, http.StatusOK, serveReq(t, newHandler(), r).Code)
	outcome, reason := outcomeAndReason(r)
	require.Equal(t, "passed_recently", outcome)
	require.Nil(t, reason)
}

func TestTokenErrorsStillWrapInvalid(t *testing.T) {
	require.True(t, errors.Is(errExpired, errInvalid))
	require.True(t, errors.Is(errBinding, errInvalid))
	require.Equal(t, "", tokenFailureReason(nil))
	require.Equal(t, reasonToken, tokenFailureReason(errInvalid))
	require.Equal(t, reasonExpired, tokenFailureReason(errExpired))
	require.Equal(t, reasonBinding, tokenFailureReason(errBinding))
}

// Fallback failures with an ordinary browser cause get their own, neutral,
// reasons (review reproductions).
func TestFallbackDoubleSubmitIsFallbackReplay(t *testing.T) {
	fb := enabledFallback()
	fb.MinDwell = time.Millisecond
	h, _ := fbHandler(DefaultPassPolicy(), fb)
	p := issue(t, h, fbIP, fbUA, "/page")
	require.Equal(t, 200, fetchPixel(t, h, p.pixel, fbIP).Code)
	time.Sleep(5 * time.Millisecond)

	first := fbPost(fbIP, fbUA, p.token, "/page", p.cookie)
	postFallback(t, h, first)
	require.Equal(t, "passed_fallback", outcomeOf(first))

	second := fbPost(fbIP, fbUA, p.token, "/page", p.cookie)
	postFallback(t, h, second)
	outcome, reason := outcomeAndReason(second)
	require.Equal(t, "failed", outcome)
	require.Equal(t, reasonFallbackReplay, reason)
}

func TestFallbackPixelOnAnotherMachineIsRenderPixel(t *testing.T) {
	fb := enabledFallback()
	fb.MinDwell = time.Millisecond
	a, _ := fbHandler(DefaultPassPolicy(), fb)
	b, _ := fbHandler(DefaultPassPolicy(), fb) // same secret, its own state
	p := issue(t, a, fbIP, fbUA, "/page")
	require.Equal(t, 200, fetchPixel(t, a, p.pixel, fbIP).Code)
	time.Sleep(5 * time.Millisecond)

	r := fbPost(fbIP, fbUA, p.token, "/page", p.cookie)
	postFallback(t, b, r)
	_, reason := outcomeAndReason(r)
	require.Equal(t, reasonRenderPixel, reason)
}

func TestFallbackFifthTabIsRenderCookie(t *testing.T) {
	fb := enabledFallback()
	fb.MinDwell = time.Millisecond
	h, _ := fbHandler(DefaultPassPolicy(), fb)
	first := issue(t, h, fbIP, fbUA, "/1")
	require.Equal(t, 200, fetchPixel(t, h, first.pixel, fbIP).Code)
	cookie := first.cookie
	for i := 0; i < fallbackCookieNonces; i++ {
		r := fbGet("/n", fbIP, fbUA)
		r.AddCookie(cookie)
		cookie = respCookie(serveReq(t, h, r), fallbackCookieName)
	}
	time.Sleep(5 * time.Millisecond)
	r := fbPost(fbIP, fbUA, first.token, "/1", cookie)
	postFallback(t, h, r)
	_, reason := outcomeAndReason(r)
	require.Equal(t, reasonRenderCookie, reason)
}

func TestFallbackCookieSaysSoOnLaterRequests(t *testing.T) {
	fb := enabledFallback()
	fb.MinDwell = time.Millisecond
	h, _ := fbHandler(DefaultPassPolicy(), fb)
	p := issue(t, h, fbIP, fbUA, "/page")
	require.Equal(t, 200, fetchPixel(t, h, p.pixel, fbIP).Code)
	time.Sleep(5 * time.Millisecond)
	w := postFallback(t, h, fbPost(fbIP, fbUA, p.token, "/page", p.cookie))
	pass := respCookie(w, CookieName)
	require.NotNil(t, pass)

	later := fbGet("/page", fbIP, fbUA)
	later.AddCookie(pass)
	require.Equal(t, "UPSTREAM", serveReq(t, h, later).Body.String())
	outcome, reason := outcomeAndReason(later)
	require.Equal(t, "passed_recently", outcome)
	require.Equal(t, reasonFallback, reason)

	// A solved cookie, and any cookie from an older image (no "f"), stays a plain pass.
	solved := fbGet("/page", fbIP, fbUA)
	solved.AddCookie(&http.Cookie{Name: CookieName, Value: IssueCookie(fbSecret, fbIP, timeNowPlus10())})
	require.Equal(t, "UPSTREAM", serveReq(t, h, solved).Body.String())
	outcome, reason = outcomeAndReason(solved)
	require.Equal(t, "passed_recently", outcome)
	require.Nil(t, reason)
}

func TestRollingRenewalKeepsFallbackProvenance(t *testing.T) {
	pol := DefaultPassPolicy()
	pol.MaxTTL = 4 * time.Hour
	now := time.Now()
	c := issuePassCookie("h-secret", pol, "203.0.113.5", "", now.Add(-time.Hour), now.Add(60*time.Second), true)
	r := browserReq("/x")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: c})
	w := serveReq(t, policyHandler(pol), r)
	renewed := passCookieHeader(t, w)
	require.NotNil(t, renewed, "due for renewal")
	pc, ok := VerifyPassCookie("h-secret", pol, renewed.Value, "203.0.113.5", "", time.Now())
	require.True(t, ok)
	require.True(t, pc.Fallback)
}

func TestPrefetchIsIssuedOther(t *testing.T) {
	for _, hdr := range []map[string]string{
		{"Sec-Purpose": "prefetch"},
		{"Sec-Purpose": "prefetch;prerender"},
		{"Purpose": "prefetch"},
	} {
		r := browserReq("/next")
		r.Header.Set("Sec-Fetch-Dest", "document")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		require.Equal(t, http.StatusOK, serveReq(t, newHandler(), r).Code)
		outcome, reason := outcomeAndReason(r)
		require.Equal(t, "issued", outcome)
		require.Equal(t, reasonOther, reason, "%v", hdr)
	}
}

// solutionBetween returns a solution meeting lo but not hi leading zero bits.
func solutionBetween(tok string, lo, hi int) string {
	for i := 0; ; i++ {
		s := strconv.Itoa(i)
		if z := leadingZeroBits(tok, s); z >= lo && z < hi {
			return s
		}
	}
}

func TestSolveAtThePreviousDifficultyIsStaleDifficulty(t *testing.T) {
	tok := IssueChallenge("h-secret", "203.0.113.5", "/", time.Now().Add(challengeTokenTTL))
	form := url.Values{"challenge": {tok}, "solution": {solutionBetween(tok, 8, 12)}}

	// Raised 8 -> 10 -> 12 within the window: every difficulty in force counts.
	raised := &ChallengeHandler{app: fakeApp{sec: "h-secret", diff: 12, vp: "/__apx_challenge/verify", prev: []int{10, 8}}}
	r := verifyReq(form, "203.0.113.5", "UA")
	require.Equal(t, http.StatusForbidden, serveReq(t, raised, r).Code)
	_, reason := outcomeAndReason(r)
	require.Equal(t, reasonStaleDifficulty, reason)

	// No recent change: the same short proof is a wrong proof.
	steady := &ChallengeHandler{app: fakeApp{sec: "h-secret", diff: 12, vp: "/__apx_challenge/verify"}}
	r = verifyReq(form, "203.0.113.5", "UA")
	require.Equal(t, http.StatusForbidden, serveReq(t, steady, r).Code)
	_, reason = outcomeAndReason(r)
	require.Equal(t, reasonProof, reason)

	// A proof that meets none of them is a wrong proof even right after a change.
	r = verifyReq(url.Values{"challenge": {tok}, "solution": {failingSolution(tok, 8)}}, "203.0.113.5", "UA")
	require.Equal(t, http.StatusForbidden, serveReq(t, raised, r).Code)
	_, reason = outcomeAndReason(r)
	require.Equal(t, reasonProof, reason)
}

func TestDifficultyHistoryKeepsEveryDifficultyInTheWindow(t *testing.T) {
	d := &difficultyHistory{}
	now := time.Now()
	d.record(16, now)
	d.record(16, now) // a reload with the same difficulty is no change
	require.Empty(t, d.replacedSince(now.Add(-staleDifficultyWindow)))

	// 16 -> 18 -> 20 within five minutes: both earlier ones are remembered.
	d.record(18, now.Add(time.Minute))
	d.record(20, now.Add(2*time.Minute))
	at := now.Add(3 * time.Minute)
	require.ElementsMatch(t, []int{16, 18}, d.replacedSince(at.Add(-staleDifficultyWindow)))

	// 16 stopped at +1m: forgotten once that is more than the window ago.
	later := now.Add(time.Minute + staleDifficultyWindow + time.Second)
	require.ElementsMatch(t, []int{18}, d.replacedSince(later.Add(-staleDifficultyWindow)))

	// Back to 16: the current difficulty is never listed.
	d.record(16, now.Add(4*time.Minute))
	require.ElementsMatch(t, []int{18, 20}, d.replacedSince(now.Add(4*time.Minute).Add(-staleDifficultyWindow)))
}

func TestDifficultyHistoryIsBounded(t *testing.T) {
	d := &difficultyHistory{}
	now := time.Now()
	for i := 0; i < 3*maxDifficultyHistory; i++ {
		d.record(10+i, now)
	}
	require.Len(t, d.replacedSince(now.Add(-time.Minute)), maxDifficultyHistory)

	// Entries older than the window are dropped, not just hidden.
	old := &difficultyHistory{}
	old.record(10, now)
	old.record(11, now)
	old.record(12, now.Add(staleDifficultyWindow+2*time.Second))
	require.Equal(t, []replacedDifficulty{{difficulty: 11, until: now.Add(staleDifficultyWindow + 2*time.Second)}}, old.replaced)
}

func TestDifficultyIsRecordedOnlyWhenTheConfigStarts(t *testing.T) {
	h := &difficultyHistory{}
	start := func(cfg *ChallengeApp) error {
		cfg.difficulties = h
		if err := cfg.Provision(caddy.Context{}); err != nil {
			return err
		}
		return cfg.Start()
	}
	require.NoError(t, start(&ChallengeApp{SecretCfg: "s", DifficultyCfg: 16}))
	require.NoError(t, start(&ChallengeApp{SecretCfg: "s", DifficultyCfg: 20}))

	// A config rejected at Provision never reaches Start, and changes nothing.
	require.Error(t, start(&ChallengeApp{SecretCfg: "s", DifficultyCfg: 18, PassIdleTTLSecondsCfg: 1}))
	// Provisioned but never started (Caddy rejected the config elsewhere): nothing either.
	unstarted := &ChallengeApp{SecretCfg: "s", DifficultyCfg: 22, difficulties: h}
	require.NoError(t, unstarted.Provision(caddy.Context{}))

	live := &ChallengeApp{SecretCfg: "s", DifficultyCfg: 20, difficulties: h}
	require.NoError(t, live.Provision(caddy.Context{}))
	require.Equal(t, []int{16}, live.PreviousDifficulties(time.Now()))
}

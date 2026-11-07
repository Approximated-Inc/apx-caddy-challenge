package apxchallenge

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

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

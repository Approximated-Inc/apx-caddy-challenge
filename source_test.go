package apxchallenge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
)

const srcIP = "203.0.113.5"

var regexpChallenge = regexp.MustCompile(`name="challenge" value="([^"]+)"`)

func srcHandler(source string) *ChallengeHandler {
	h := newHandler()
	h.Source = source
	return h
}

func srcVar(r *http.Request) any {
	return caddyhttp.GetVar(r.Context(), sourceVarKey)
}

func soonExp() time.Time { return time.Now().Add(challengeTokenTTL) }

// postVerify posts a solved or unsolved challenge token to h from ip and
// returns the request so the vars can be read.
func postSolution(t *testing.T, h *ChallengeHandler, tok, solution, ip string) *http.Request {
	t.Helper()
	r := verifyReq(url.Values{"challenge": {tok}, "solution": {solution}}, ip, "UA")
	serveReq(t, h, r)
	return r
}

// tokenBody decodes the signed body of a token into a generic map.
func tokenBody(t *testing.T, tok string) map[string]any {
	t.Helper()
	body, err := splitVerify("h-secret", challengeDomain, tok)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m))
	return m
}

// pageToken serves one challenge page from h to ip and returns its PoW token.
func pageToken(t *testing.T, h *ChallengeHandler, ip string) string {
	t.Helper()
	r := browserReq("/page")
	r.RemoteAddr = net.JoinHostPort(ip, "443")
	w := serveReq(t, h, r)
	m := regexpChallenge.FindStringSubmatch(w.Body.String())
	require.NotNil(t, m)
	return m[1]
}

func TestSourceRoundTripsInToken(t *testing.T) {
	tok := pageToken(t, srcHandler(sourceStaff), srcIP)
	m := tokenBody(t, tok)
	require.Equal(t, "staff", m["s"])
	require.Equal(t, srcIP, m["a"])

	p, err := VerifyChallenge("h-secret", tok, srcIP)
	require.NoError(t, err)
	require.Equal(t, "staff", p.Source)
	require.Equal(t, srcIP, p.Addr)

	// IPv6 is canonical: the compressed form of the requester's address.
	tok6 := pageToken(t, srcHandler(sourceAutomatic), "2001:0db8:0000:0000:0000:0000:0000:0001")
	require.Equal(t, "2001:db8::1", tokenBody(t, tok6)["a"])

	// The fallback token carries both claims too.
	h, app := fbHandler(DefaultPassPolicy(), enabledFallback())
	h.Source = sourceCustomer
	ftok := issue(t, h, fbIP, fbUA, "/x").token
	fp, err := verifyFallbackToken(fbSecret, app.pol, ftok, fbIP, fbUA, time.Now())
	require.NoError(t, err)
	require.Equal(t, "customer", fp.Source)
	require.Equal(t, fbIP, fp.Addr)
}

func TestEmptySourceTokenIsByteIdentical(t *testing.T) {
	exp := time.Unix(goldenExpUnix, 0)
	got := issueChallengeNonce(goldenSecret, DefaultPassPolicy(), "203.0.113.5", "Mozilla/5.0", "/dash?x=1", time.Now(), exp, "AAAAAAAAAAAAAAAA")
	require.Equal(t, masterChallengeV4, got)
	require.Equal(t, got, issueChallengeNonceSource(goldenSecret, DefaultPassPolicy(), "203.0.113.5", "Mozilla/5.0", "/dash?x=1", time.Now(), exp, "AAAAAAAAAAAAAAAA", ""))
	body, err := splitVerify(goldenSecret, challengeDomain, got)
	require.NoError(t, err)
	require.NotContains(t, string(body), `"s"`)
	require.NotContains(t, string(body), `"a"`)

	now := time.Unix(goldenExpUnix-100, 0)
	// Frozen from origin/master (9683839) before this change.
	const masterFallbackToken = "eyJlIjoxODkzNDU2NTAwLCJpIjoxODkzNDU1OTAwMDAwLCJuIjoibiIsInAiOiIyMDMuMC4xMTMuMC8yNCIsInIiOiIveCJ9.qYg1BmF-U27aTlBui8x4SsFQA1jvbwy7rXgGfaElM90"
	fOld := issueFallbackTokenNonce("s", DefaultPassPolicy(), "203.0.113.5", "UA", "/x", now, "n")
	require.Equal(t, masterFallbackToken, fOld)
	require.Equal(t, masterFallbackToken, issueFallbackTokenNonceSource("s", DefaultPassPolicy(), "203.0.113.5", "UA", "/x", now, "n", ""))
	fBody, err := splitVerify("s", fallbackDomain, fOld)
	require.NoError(t, err)
	var fm map[string]any
	require.NoError(t, json.Unmarshal(fBody, &fm))
	require.NotContains(t, fm, "s")
	require.NotContains(t, fm, "a")

	// A source does change the bytes.
	require.NotEqual(t, got, issueChallengeNonceSource(goldenSecret, DefaultPassPolicy(), "203.0.113.5", "Mozilla/5.0", "/dash?x=1", time.Now(), exp, "AAAAAAAAAAAAAAAA", sourceAutomatic))
}

func TestTokenWithoutSourceRecordsUnknown(t *testing.T) {
	// A token from a route or an image with no source, verified on a route
	// that has one: the route's source must not leak onto it.
	tok := IssueChallenge("h-secret", srcIP, "/", soonExp())
	require.NotContains(t, tokenBody(t, tok), "s")

	r := postSolution(t, srcHandler(sourceAutomatic), tok, failingSolution(tok, 8), srcIP)
	outcome, reason := outcomeAndReason(r)
	require.Equal(t, "failed", outcome)
	require.Equal(t, reasonProof, reason)
	require.Equal(t, sourceUnknown, srcVar(r))

	r = postSolution(t, srcHandler(sourceAutomatic), tok, SolvePoW(tok, 8), srcIP)
	require.Equal(t, "passed", outcomeOfVar(r))
	require.Equal(t, sourceUnknown, srcVar(r))
}

func outcomeOfVar(r *http.Request) any { return caddyhttp.GetVar(r.Context(), outcomeVarKey) }

func TestNewTokenDecodesWithPreSourcePayload(t *testing.T) {
	// The payload shape before this change, decoded as an older plugin does.
	type preSourcePayload struct {
		Exp    int64  `json:"e"`
		Nonce  string `json:"n"`
		Prefix string `json:"p"`
		Ret    string `json:"r"`
		UA     string `json:"u,omitempty"`
		Iat    int64  `json:"i,omitempty"`
	}
	tok := issuePassChallengeSource("h-secret", DefaultPassPolicy(), srcIP, "UA", "/dest", soonExp(), sourceAutomatic)
	body, err := splitVerify("h-secret", challengeDomain, tok)
	require.NoError(t, err)
	var old preSourcePayload
	require.NoError(t, json.Unmarshal(body, &old))
	require.Equal(t, "/dest", old.Ret)
	require.NotEmpty(t, old.Nonce)
	require.Equal(t, "203.0.113.0/24", old.Prefix)

	// And a token without the keys decodes into the new struct with empty claims.
	p, err := VerifyChallenge("h-secret", IssueChallenge("h-secret", srcIP, "/", soonExp()), srcIP)
	require.NoError(t, err)
	require.Empty(t, p.Source)
	require.Empty(t, p.Addr)
}

func TestForgedTokenIsUnknown(t *testing.T) {
	other := issuePassChallengeSource("other-secret", DefaultPassPolicy(), srcIP, "UA", "/", soonExp(), sourceAutomatic)
	// A forged token that even claims automatic and the right address.
	forged := func(secret string, exp time.Time) string {
		p := ChallengePayload{Exp: exp.Unix(), Nonce: "n", Prefix: "203.0.113.0/24", Ret: "/", Source: sourceAutomatic, Addr: srcIP}
		body, _ := json.Marshal(p)
		return encodeSigned(secret, challengeDomain, body)
	}
	for name, tok := range map[string]string{
		"another secret":        other,
		"forged claims":         forged("not-the-secret", soonExp()),
		"forged expired claims": forged("not-the-secret", time.Now().Add(-time.Minute)),
		"garbage":               "garbage",
		"empty":                 "",
		"valid body, no sig":    base64.RawURLEncoding.EncodeToString([]byte(`{"s":"automatic"}`)) + ".",
		"mangled body":          strings.Replace(IssueChallenge("h-secret", srcIP, "/", soonExp()), ".", "x.", 1),
	} {
		t.Run(name, func(t *testing.T) {
			r := postSolution(t, srcHandler(sourceStaff), tok, "1", srcIP)
			outcome, reason := outcomeAndReason(r)
			require.Equal(t, "failed", outcome)
			require.Equal(t, sourceUnknown, srcVar(r), "reason %v", reason)
		})
	}

	// Editing the signed body, even to a valid source, breaks the signature.
	good := issuePassChallengeSource("h-secret", DefaultPassPolicy(), srcIP, "UA", "/", soonExp(), sourceStaff)
	dot := strings.LastIndexByte(good, '.')
	body, _ := base64.RawURLEncoding.DecodeString(good[:dot])
	edited := strings.Replace(string(body), `"s":"staff"`, `"s":"automatic"`, 1)
	require.NotEqual(t, string(body), edited)
	tampered := base64.RawURLEncoding.EncodeToString([]byte(edited)) + good[dot:]
	r := postSolution(t, srcHandler(sourceStaff), tampered, "1", srcIP)
	require.Equal(t, reasonToken, reasonOfVar(r))
	require.Equal(t, sourceUnknown, srcVar(r))
}

func reasonOfVar(r *http.Request) any { return caddyhttp.GetVar(r.Context(), reasonVarKey) }

func TestExpiredKeepsAuthenticSource(t *testing.T) {
	expired := issuePassChallengeSource("h-secret", DefaultPassPolicy(), srcIP, "UA", "/", time.Now().Add(-time.Second), sourceAutomatic)
	r := postSolution(t, srcHandler(sourceStaff), expired, "1", srcIP)
	require.Equal(t, reasonExpired, reasonOfVar(r))
	require.Equal(t, sourceAutomatic, srcVar(r))

	// An expired token from another address in the network is unknown.
	r = postSolution(t, srcHandler(sourceStaff), expired, "1", "203.0.113.9")
	require.Equal(t, reasonExpired, reasonOfVar(r))
	require.Equal(t, sourceUnknown, srcVar(r))

	// An expired token with no source claim is unknown.
	r = postSolution(t, srcHandler(sourceStaff), IssueChallenge("h-secret", srcIP, "/", time.Now().Add(-time.Second)), "1", srcIP)
	require.Equal(t, reasonExpired, reasonOfVar(r))
	require.Equal(t, sourceUnknown, srcVar(r))

	// The fallback token too.
	h, app := fbHandler(DefaultPassPolicy(), enabledFallback())
	old := issueFallbackTokenNonceSource(fbSecret, app.pol, fbIP, fbUA, "/x", time.Now().Add(-fallbackTokenTTL-time.Minute), "nonce", sourceStaff)
	fr := fbPost(fbIP, fbUA, old, "/x")
	postFallback(t, h, fr)
	require.Equal(t, reasonExpired, reasonOfVar(fr))
	require.Equal(t, sourceStaff, srcVar(fr))
}

func TestBindingIsUnknown(t *testing.T) {
	// Issued to a client in another network: the requester is never its address.
	tok := issuePassChallengeSource("h-secret", DefaultPassPolicy(), "198.51.100.7", "UA", "/", soonExp(), sourceAutomatic)
	r := postSolution(t, srcHandler(sourceAutomatic), tok, SolvePoW(tok, 8), srcIP)
	require.Equal(t, reasonBinding, reasonOfVar(r))
	require.Equal(t, sourceUnknown, srcVar(r))

	// Same under UA binding: right address, wrong UA.
	pol := DefaultPassPolicy()
	pol.BindUserAgent = true
	uaTok := issuePassChallengeSource("h-secret", pol, srcIP, "UA-2", "/", soonExp(), sourceAutomatic)
	h := policyHandler(pol)
	r = verifyReq(url.Values{"challenge": {uaTok}, "solution": {SolvePoW(uaTok, 8)}}, srcIP, "UA-1")
	serveReq(t, h, r)
	require.Equal(t, reasonBinding, reasonOfVar(r))
	require.Equal(t, sourceUnknown, srcVar(r))

	// The fallback token's binding failure.
	fh, app := fbHandler(DefaultPassPolicy(), enabledFallback())
	ftok := issueFallbackTokenNonceSource(fbSecret, app.pol, "198.51.100.7", fbUA, "/x", time.Now(), "nonce", sourceAutomatic)
	fr := fbPost(fbIP, fbUA, ftok, "/x")
	postFallback(t, fh, fr)
	require.Equal(t, reasonBinding, reasonOfVar(fr))
	require.Equal(t, sourceUnknown, srcVar(fr))

	// Fallback token bound to a UA, posted from its own issued address with
	// another UA: the address matches, so only the binding rule makes it unknown.
	upol := DefaultPassPolicy()
	upol.BindUserAgent = true
	uh, _ := fbHandler(upol, enabledFallback())
	utok := issueFallbackTokenNonceSource(fbSecret, upol, fbIP, "UA-2", "/x", time.Now(), "nonce", sourceAutomatic)
	ur := fbPost(fbIP, "UA-1", utok, "/x")
	postFallback(t, uh, ur)
	require.Equal(t, reasonBinding, reasonOfVar(ur))
	require.Equal(t, sourceUnknown, srcVar(ur))
}

func TestReplayedTokenFromAnotherAddressIsUnknown(t *testing.T) {
	tok := issuePassChallengeSource("h-secret", DefaultPassPolicy(), "203.0.113.5", "UA", "/", soonExp(), sourceAutomatic)
	const other = "203.0.113.9" // same /24, so the token verifies

	r := postSolution(t, srcHandler(""), tok, failingSolution(tok, 8), other)
	require.Equal(t, "failed", outcomeOfVar(r))
	require.Equal(t, reasonProof, reasonOfVar(r))
	require.Equal(t, sourceUnknown, srcVar(r))

	r = postSolution(t, srcHandler(""), tok, SolvePoW(tok, 8), other)
	require.Equal(t, "passed", outcomeOfVar(r))
	require.Equal(t, sourceUnknown, srcVar(r))

	// The issued address itself earns the source, failing or passing.
	r = postSolution(t, srcHandler(""), tok, failingSolution(tok, 8), "203.0.113.5")
	require.Equal(t, reasonProof, reasonOfVar(r))
	require.Equal(t, sourceAutomatic, srcVar(r))
	r = postSolution(t, srcHandler(""), tok, SolvePoW(tok, 8), "203.0.113.5")
	require.Equal(t, "passed", outcomeOfVar(r))
	require.Equal(t, sourceAutomatic, srcVar(r))
}

func TestFallbackTokenFromAnotherAddressIsUnknown(t *testing.T) {
	fb := enabledFallback()
	fb.MinDwell = time.Millisecond
	h, app := fbHandler(DefaultPassPolicy(), fb)
	const nonce = "AAAAAAAAAAAAAAAA"
	tok := issueFallbackTokenNonceSource(fbSecret, app.pol, "203.0.113.5", fbUA, "/x", time.Now().Add(-time.Minute), nonce, sourceAutomatic)

	// Verifies from another address in the /24, then fails the cookie check.
	r := fbPost("203.0.113.9", fbUA, tok, "/x")
	postFallback(t, h, r)
	require.Equal(t, "failed", outcomeOf(r))
	require.Equal(t, reasonRenderCookie, reasonOfVar(r))
	require.Equal(t, sourceUnknown, srcVar(r))

	// The same post from the issued address records the source.
	r = fbPost("203.0.113.5", fbUA, tok, "/x")
	postFallback(t, h, r)
	require.Equal(t, reasonRenderCookie, reasonOfVar(r))
	require.Equal(t, sourceAutomatic, srcVar(r))

	// A pass from the other address is unknown too.
	h2 := &ChallengeHandler{app: fbApp{fakeApp: app.fakeApp, pol: app.pol, fb: fb, replay: NewNonceLRU(16), state: renderedState(nonce)}}
	r = fbPost("203.0.113.9", fbUA, tok, "/x", fbCookie(fbSecret, nonce))
	postFallback(t, h2, r)
	require.Equal(t, "passed_fallback", outcomeOf(r))
	require.Equal(t, sourceUnknown, srcVar(r))
}

func TestMappedAddressMatches(t *testing.T) {
	require.True(t, addrMatches("::ffff:203.0.113.5", "203.0.113.5"))
	require.True(t, addrMatches("203.0.113.5", "::ffff:203.0.113.5"))
	require.True(t, addrMatches("2001:db8::1", "2001:0db8:0:0:0:0:0:1"))
	require.False(t, addrMatches("203.0.113.5", "203.0.113.9"))
	require.False(t, addrMatches("", "203.0.113.5"))
	require.False(t, addrMatches("203.0.113.5", ""))
	require.False(t, addrMatches("", ""))

	// End to end: a token whose claim is the mapped spelling still attributes.
	p := ChallengePayload{Exp: soonExp().Unix(), Nonce: "n", Prefix: "203.0.113.0/24", Ret: "/", Source: sourceAutomatic, Addr: "::ffff:203.0.113.5"}
	body, _ := json.Marshal(p)
	tok := encodeSigned("h-secret", challengeDomain, body)
	r := postSolution(t, srcHandler(""), tok, failingSolution(tok, 8), "203.0.113.5")
	require.Equal(t, reasonProof, reasonOfVar(r))
	require.Equal(t, sourceAutomatic, srcVar(r))
}

func TestVerifyRouteUsesTokenNotHandlerSource(t *testing.T) {
	tok := issuePassChallengeSource("h-secret", DefaultPassPolicy(), srcIP, "UA", "/", soonExp(), sourceAutomatic)
	h := srcHandler(sourceStaff)
	r := postSolution(t, h, tok, failingSolution(tok, 8), srcIP)
	require.Equal(t, reasonProof, reasonOfVar(r))
	require.Equal(t, sourceAutomatic, srcVar(r))
	r = postSolution(t, h, tok, SolvePoW(tok, 8), srcIP)
	require.Equal(t, sourceAutomatic, srcVar(r))
}

func TestVerifyPathGetIsUnknown(t *testing.T) {
	// The shared verify route has no source, so a GET to its own path is a page
	// it served itself.
	r := browserReq(defaultVerifyPath)
	require.Equal(t, http.StatusOK, serveReq(t, srcHandler(""), r).Code)
	require.Equal(t, "issued", outcomeOfVar(r))
	require.Equal(t, sourceUnknown, srcVar(r))
	// Its page's token carries no claims.
	require.NotContains(t, tokenBody(t, pageToken(t, srcHandler(""), srcIP)), "s")
}

func TestEveryOutcomeSetsSourceVar(t *testing.T) {
	const src = sourceEdgeSequence
	// Route outcomes carry the route's source.
	routeCases := []struct {
		name    string
		mutate  func(r *http.Request)
		outcome string
		reason  string
	}{
		{"issued document", func(r *http.Request) {}, "issued", reasonDocument},
		{"issued other", func(r *http.Request) { r.Header.Set("Accept", "*/*") }, "issued", reasonOther},
		{"not shown api", func(r *http.Request) { r.Header.Set("Accept", "application/json") }, "failed", reasonAPI},
		{"not shown stream", func(r *http.Request) { r.Header.Set("Upgrade", "websocket") }, "failed", reasonStream},
		{"passed recently", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: CookieName, Value: IssueCookie("h-secret", srcIP, timeNowPlus10())})
		}, "passed_recently", ""},
	}
	for _, tc := range routeCases {
		t.Run(tc.name, func(t *testing.T) {
			r := browserReq("/page")
			tc.mutate(r)
			serveReq(t, srcHandler(src), r)
			outcome, reason := outcomeAndReason(r)
			require.Equal(t, tc.outcome, outcome)
			if tc.reason != "" {
				require.Equal(t, tc.reason, reason)
			}
			require.Equal(t, src, srcVar(r))
		})
	}

	// passed_recently_fallback, on a route and on the shared verify route.
	fallbackPass := &http.Cookie{Name: CookieName, Value: issuePassCookie("h-secret", DefaultPassPolicy(), srcIP, "", time.Time{}, timeNowPlus10(), true)}
	r := browserReq("/page")
	r.AddCookie(fallbackPass)
	serveReq(t, srcHandler(src), r)
	require.Equal(t, reasonFallback, reasonOfVar(r))
	require.Equal(t, src, srcVar(r))
	r = browserReq("/page")
	r.AddCookie(fallbackPass)
	serveReq(t, srcHandler(""), r)
	require.Equal(t, sourceUnknown, srcVar(r))

	// Verify outcomes carry the token's source, under a handler of another one.
	pol := DefaultPassPolicy()
	pol.IPv4Prefix = 32
	tokenSrc := sourceAutomatic
	mint := func(p PassPolicy, exp time.Time) string {
		return issuePassChallengeSource("h-secret", p, srcIP, "UA", "/", exp, tokenSrc)
	}
	history := &difficultyHistory{}
	issuePage(t, handlerAt(4, history))
	staleHandler := handlerAt(12, history)
	staleTok := mint(DefaultPassPolicy(), soonExp())

	replayHandler := policyHandler(pol)
	replayTok := mint(pol, soonExp())
	postSolution(t, replayHandler, replayTok, SolvePoW(replayTok, 8), srcIP) // spends it

	proofTok := mint(DefaultPassPolicy(), soonExp())
	verifyCases := []struct {
		name            string
		h               *ChallengeHandler
		tok, solution   string
		outcome, reason string
	}{
		{"passed", srcHandler(sourceStaff), proofTok, SolvePoW(proofTok, 8), "passed", ""},
		{"failed proof", srcHandler(sourceStaff), proofTok, failingSolution(proofTok, 8), "failed", reasonProof},
		{"failed stale difficulty", staleHandler, staleTok, solutionBetween(staleTok, 4, 12), "failed", reasonStaleDifficulty},
		{"failed replay", replayHandler, replayTok, SolvePoW(replayTok, 8), "failed", reasonReplay},
		{"failed expired", srcHandler(sourceStaff), mint(DefaultPassPolicy(), time.Now().Add(-time.Second)), "1", "failed", reasonExpired},
	}
	for _, tc := range verifyCases {
		t.Run(tc.name, func(t *testing.T) {
			r := postSolution(t, tc.h, tc.tok, tc.solution, srcIP)
			require.Equal(t, tc.outcome, outcomeOfVar(r))
			if tc.reason != "" {
				require.Equal(t, tc.reason, reasonOfVar(r))
			}
			require.Equal(t, sourceAutomatic, srcVar(r))
		})
	}

	// failed_binding and failed_token are always unknown.
	require.Equal(t, sourceUnknown, srcVar(postSolution(t, srcHandler(sourceStaff), mint(DefaultPassPolicy(), soonExp()), "1", "198.51.100.77")))
	require.Equal(t, sourceUnknown, srcVar(postSolution(t, srcHandler(sourceStaff), "garbage", "1", srcIP)))
}

func TestFallbackOutcomesCarrySource(t *testing.T) {
	fb := enabledFallback()
	fb.MinDwell = time.Millisecond
	const nonce = "AAAAAAAAAAAAAAAA"
	app := func(state *FallbackState) fbApp {
		return fbApp{fakeApp: fakeApp{sec: fbSecret, diff: 8, vp: fbVP}, pol: DefaultPassPolicy(), fb: fb, replay: NewNonceLRU(16), state: state}
	}
	mint := func(age time.Duration) string {
		return issueFallbackTokenNonceSource(fbSecret, DefaultPassPolicy(), fbIP, fbUA, "/x", time.Now().Add(-age), nonce, sourceAutomatic)
	}
	post := func(h *ChallengeHandler, tok string, cookies ...*http.Cookie) *http.Request {
		r := fbPost(fbIP, fbUA, tok, "/x", cookies...)
		postFallback(t, h, r)
		return r
	}
	newH := func(state *FallbackState) *ChallengeHandler {
		h := &ChallengeHandler{app: app(state)}
		h.Source = sourceStaff // the route's own source must never win
		return h
	}

	// passed_fallback
	r := post(newH(renderedState(nonce)), mint(time.Minute), fbCookie(fbSecret, nonce))
	require.Equal(t, "passed_fallback", outcomeOf(r))
	require.Equal(t, sourceAutomatic, srcVar(r))

	cases := []struct {
		name   string
		state  *FallbackState
		age    time.Duration
		cookie *http.Cookie
		reason string
	}{
		{"render cookie", renderedState(nonce), time.Minute, nil, reasonRenderCookie},
		{"render pixel", NewFallbackState(16), time.Minute, fbCookie(fbSecret, nonce), reasonRenderPixel},
		{"render dwell", renderedState(nonce), 0, fbCookie(fbSecret, nonce), reasonRenderDwell},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cookies []*http.Cookie
			if tc.cookie != nil {
				cookies = append(cookies, tc.cookie)
			}
			r := post(newH(tc.state), mint(tc.age), cookies...)
			require.Equal(t, "failed", outcomeOf(r))
			require.Equal(t, tc.reason, reasonOfVar(r))
			require.Equal(t, sourceAutomatic, srcVar(r))
		})
	}

	t.Run("fallback replay", func(t *testing.T) {
		h := newH(renderedState(nonce))
		post(h, mint(time.Minute), fbCookie(fbSecret, nonce))
		r := post(h, mint(time.Minute), fbCookie(fbSecret, nonce))
		require.Equal(t, reasonFallbackReplay, reasonOfVar(r))
		require.Equal(t, sourceAutomatic, srcVar(r))
	})

	t.Run("fallback limit", func(t *testing.T) {
		st := renderedState(nonce)
		a := app(st)
		a.fb.MaxPerHour = 1
		h := &ChallengeHandler{app: a}
		// A second nonce, so the first pass spends the budget and this one hits it.
		const nonce2 = "BBBBBBBBBBBBBBBB"
		st.Rendered.Add(nonce2, time.Now().Add(fallbackTokenTTL), time.Now())
		post(h, mint(time.Minute), fbCookie(fbSecret, nonce))
		tok2 := issueFallbackTokenNonceSource(fbSecret, DefaultPassPolicy(), fbIP, fbUA, "/x", time.Now().Add(-time.Minute), nonce2, sourceAutomatic)
		r := post(h, tok2, fbCookie(fbSecret, nonce2))
		require.Equal(t, reasonFallbackLimit, reasonOfVar(r))
		require.Equal(t, sourceAutomatic, srcVar(r))
	})

	t.Run("no claims", func(t *testing.T) {
		tok := issueFallbackTokenNonce(fbSecret, DefaultPassPolicy(), fbIP, fbUA, "/x", time.Now().Add(-time.Minute), nonce)
		r := post(newH(renderedState(nonce)), tok, fbCookie(fbSecret, nonce))
		require.Equal(t, "passed_fallback", outcomeOf(r))
		require.Equal(t, sourceUnknown, srcVar(r))
	})

	t.Run("token failures", func(t *testing.T) {
		r := post(newH(renderedState(nonce)), "garbage")
		require.Equal(t, reasonToken, reasonOfVar(r))
		require.Equal(t, sourceUnknown, srcVar(r))
	})
}

func TestUnknownConfiguredSourceIsUnknown(t *testing.T) {
	h := srcHandler("bogus")
	require.NoError(t, h.Provision(caddy.Context{Context: context.Background()}))
	require.Equal(t, sourceUnknown, h.Source)

	r := browserReq("/page")
	w := serveReq(t, h, r)
	require.Equal(t, sourceUnknown, srcVar(r))
	m := regexpChallenge.FindStringSubmatch(w.Body.String())
	require.NotNil(t, m)
	require.Equal(t, sourceUnknown, tokenBody(t, m[1])["s"])

	// Without Provision the recorded value is still normalised.
	r = browserReq("/page")
	serveReq(t, srcHandler("Automatic "), r)
	require.Equal(t, sourceUnknown, srcVar(r))

	// Every configured value is kept as is.
	for _, s := range []string{sourceAutomatic, sourceStaff, sourceCustomer, sourceEdgeSequence, sourceReputation} {
		r := browserReq("/page")
		serveReq(t, srcHandler(s), r)
		require.Equal(t, s, srcVar(r))
	}
}

func TestStrictConfigAcceptsSource(t *testing.T) {
	var h ChallengeHandler
	require.NoError(t, caddy.StrictUnmarshalJSON([]byte(`{"source":"automatic"}`), &h))
	require.Equal(t, sourceAutomatic, h.Source)

	var bare ChallengeHandler
	require.NoError(t, caddy.StrictUnmarshalJSON([]byte(`{}`), &bare))
	require.Empty(t, bare.Source)

	out, err := json.Marshal(&ChallengeHandler{})
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(out), "an unset source adds no key to the handler JSON")

	var bad ChallengeHandler
	require.Error(t, caddy.StrictUnmarshalJSON([]byte(`{"sourc":"automatic"}`), &bad))
}

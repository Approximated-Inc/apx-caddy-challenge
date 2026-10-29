package apxchallenge

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

// legacyIssueCookie / legacyVerifyCookie are verbatim copies of the pre-policy
// IssueCookie / VerifyCookie (master 15fc6a5), kept to prove the default policy
// is wire-compatible in both directions.
type legacyCookiePayload struct {
	Exp    int64  `json:"e"`
	Prefix string `json:"p"`
}

func legacyIssueCookie(secret, ip string, exp time.Time) string {
	pref, _ := clientPrefix(ip)
	body, _ := json.Marshal(legacyCookiePayload{Exp: exp.Unix(), Prefix: pref})
	return encodeSigned(secret, cookieDomain, body)
}

func legacyVerifyCookie(secret, cookie, ip string) bool {
	body, err := splitVerify(secret, cookieDomain, cookie)
	if err != nil {
		return false
	}
	var p legacyCookiePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return false
	}
	if time.Now().Unix() > p.Exp {
		return false
	}
	pref, ok := clientPrefix(ip)
	return ok && p.Prefix == pref
}

func decodePayload(t *testing.T, cookie string) map[string]any {
	t.Helper()
	body, err := base64.RawURLEncoding.DecodeString(cookie[:strings.LastIndex(cookie, ".")])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m))
	return m
}

// Literals produced by master 15fc6a5's own cookie.go (IssueCookie, and the
// json.Marshal + encodeSigned body of IssueChallenge with a fixed nonce) for
// secret "golden-secret", exp 1893456000 (2030-01-01). They pin the payload
// shape AND the HMAC construction, so a change to either breaks them.
const (
	masterCookieV4    = "eyJlIjoxODkzNDU2MDAwLCJwIjoiMjAzLjAuMTEzLjAvMjQifQ.LrM1c0hxWRmj-1Rq72vpDeI7hhp-hqhmP3PJ4cMoQ38"
	masterCookieV6    = "eyJlIjoxODkzNDU2MDAwLCJwIjoiMjAwMTpkYjg6MToyOjovNjQifQ.daepoAQmzg7JqfR9E-DnbJXmSowFPwCoDBWQaCxgJf4"
	masterChallengeV4 = "eyJlIjoxODkzNDU2MDAwLCJuIjoiQUFBQUFBQUFBQUFBQUFBQSIsInAiOiIyMDMuMC4xMTMuMC8yNCIsInIiOiIvZGFzaD94PTEifQ.rDsSONjtY7d_xNynCFAolyA7ngPE2urtOu6t-WlcoDA"
	goldenSecret      = "golden-secret"
	goldenExpUnix     = 1893456000
)

func TestDefaultPolicyCookieGolden(t *testing.T) {
	exp := time.Unix(goldenExpUnix, 0)

	// New code issues exactly master's bytes.
	require.Equal(t, masterCookieV4, IssuePassCookie(goldenSecret, DefaultPassPolicy(), "203.0.113.5", "Mozilla/5.0", time.Unix(goldenExpUnix-600, 0), exp))
	require.Equal(t, masterCookieV4, IssueCookie(goldenSecret, "203.0.113.5", exp))
	require.Equal(t, masterCookieV6, IssuePassCookie(goldenSecret, DefaultPassPolicy(), "2001:db8:1:2:3:4:5:6", "", time.Time{}, exp))

	// Master's bytes verify under the new code (valid until 2030).
	now := time.Now()
	pc, ok := VerifyPassCookie(goldenSecret, DefaultPassPolicy(), masterCookieV4, "203.0.113.250", "any", now)
	require.True(t, ok)
	require.Equal(t, int64(goldenExpUnix), pc.Exp.Unix())
	require.True(t, VerifyCookie(goldenSecret, masterCookieV4, "203.0.113.1"))
	require.True(t, VerifyCookie(goldenSecret, masterCookieV6, "2001:db8:1:2::99"))
	require.False(t, VerifyCookie(goldenSecret, masterCookieV4, "203.0.114.1"))
}

func TestDefaultPolicyChallengeGolden(t *testing.T) {
	exp := time.Unix(goldenExpUnix, 0)
	require.Equal(t, masterChallengeV4, issueChallengeNonce(goldenSecret, DefaultPassPolicy(), "203.0.113.5", "Mozilla/5.0", "/dash?x=1", exp, "AAAAAAAAAAAAAAAA"))

	p, err := VerifyChallenge(goldenSecret, masterChallengeV4, "203.0.113.9")
	require.NoError(t, err)
	require.Equal(t, "/dash?x=1", p.Ret)
	require.Equal(t, "AAAAAAAAAAAAAAAA", p.Nonce)
	_, err = VerifyPassChallenge(goldenSecret, DefaultPassPolicy(), masterChallengeV4, "203.0.113.9", "any", time.Now())
	require.NoError(t, err)

	// A default token issued by the new code has exactly master's keys.
	tok := IssuePassChallenge(goldenSecret, DefaultPassPolicy(), "203.0.113.5", "UA", "/x", exp)
	require.ElementsMatch(t, []string{"e", "n", "p", "r"}, keys(decodePayload(t, tok)))
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestDefaultPolicyCrossVerifiesWithLegacy(t *testing.T) {
	now := time.Now()
	exp := now.Add(10 * time.Minute)

	// New default issue → legacy verify.
	c := IssuePassCookie(secret, DefaultPassPolicy(), "203.0.113.5", "ua", now, exp)
	require.True(t, legacyVerifyCookie(secret, c, "203.0.113.77"))
	require.False(t, legacyVerifyCookie(secret, c, "198.51.100.5"))

	// Legacy issue → new default verify, with or without a UA.
	old := legacyIssueCookie(secret, "203.0.113.5", exp)
	pc, ok := VerifyPassCookie(secret, DefaultPassPolicy(), old, "203.0.113.77", "anything", now)
	require.True(t, ok)
	require.Equal(t, exp.Unix(), pc.Exp.Unix())
	require.True(t, pc.IssuedAt.IsZero(), "a cookie without an issued-at reports none")
	require.True(t, VerifyCookie(secret, old, "203.0.113.77"))
	_, ok = VerifyPassCookie(secret, DefaultPassPolicy(), old, "198.51.100.5", "", now)
	require.False(t, ok)
}

func TestDefaultPolicyNeverRenews(t *testing.T) {
	pol := DefaultPassPolicy()
	require.False(t, pol.Rolling())
	now := time.Unix(1_000_000, 0)
	_, renew := pol.Renewal(PassCookie{Exp: now.Add(time.Second), IssuedAt: now.Add(-599 * time.Second)}, now)
	require.False(t, renew)
}

func rollingPolicy() PassPolicy {
	pol := DefaultPassPolicy()
	pol.MaxTTL = 4 * time.Hour
	return pol
}

func TestRenewalWindow(t *testing.T) {
	pol := rollingPolicy() // idle 600s, max 4h
	now := time.Unix(1_000_000, 0)
	iat := now.Add(-30 * time.Minute)

	cases := []struct {
		name      string
		remaining time.Duration
		renew     bool
	}{
		{"fresh", 600 * time.Second, false},
		{"just over half", 301 * time.Second, false},
		{"exactly half", 300 * time.Second, false},
		{"just under half", 299 * time.Second, true},
		{"about to expire", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exp, renew := pol.Renewal(PassCookie{Exp: now.Add(tc.remaining), IssuedAt: iat}, now)
			require.Equal(t, tc.renew, renew)
			if renew {
				require.Equal(t, now.Add(600*time.Second).Unix(), exp.Unix())
			}
		})
	}
}

func TestRenewalAbsoluteCap(t *testing.T) {
	pol := rollingPolicy() // idle 600s, max 4h
	now := time.Unix(1_000_000, 0)

	// 100s of the 4h budget left: renewal is clamped to issued_at + max.
	iat := now.Add(-4*time.Hour + 100*time.Second)
	exp, renew := pol.Renewal(PassCookie{Exp: now.Add(60 * time.Second), IssuedAt: iat}, now)
	require.True(t, renew)
	require.Equal(t, iat.Add(4*time.Hour).Unix(), exp.Unix())

	// Cap already reached: the cookie's exp IS issued_at + max, so no renewal.
	iat = now.Add(-4*time.Hour + 60*time.Second)
	_, renew = pol.Renewal(PassCookie{Exp: now.Add(60 * time.Second), IssuedAt: iat}, now)
	require.False(t, renew)

	// Past the cap entirely.
	_, renew = pol.Renewal(PassCookie{Exp: now.Add(10 * time.Second), IssuedAt: now.Add(-5 * time.Hour)}, now)
	require.False(t, renew)
}

func TestRollingCookieCarriesIssuedAtAcrossRenewal(t *testing.T) {
	pol := rollingPolicy()
	iat := time.Unix(1_000_000, 0)
	c := IssuePassCookie(secret, pol, "203.0.113.5", "", iat, iat.Add(pol.IdleTTL))
	require.Equal(t, float64(iat.Unix()), decodePayload(t, c)["i"])

	now := iat.Add(400 * time.Second)
	pc, ok := VerifyPassCookie(secret, pol, c, "203.0.113.5", "", now)
	require.True(t, ok)
	require.Equal(t, iat.Unix(), pc.IssuedAt.Unix())

	exp, renew := pol.Renewal(pc, now)
	require.True(t, renew)
	renewed := IssuePassCookie(secret, pol, "203.0.113.5", "", pc.IssuedAt, exp)
	pc2, ok := VerifyPassCookie(secret, pol, renewed, "203.0.113.5", "", now)
	require.True(t, ok)
	require.Equal(t, iat.Unix(), pc2.IssuedAt.Unix(), "renewal keeps the original solve time")
	require.Equal(t, now.Add(pol.IdleTTL).Unix(), pc2.Exp.Unix())
}

func TestCookieWithoutIssuedAtIsNeverRenewed(t *testing.T) {
	pol := DefaultPassPolicy()
	pol.IdleTTL = 86400 * time.Second
	pol.MaxTTL = 604800 * time.Second
	now := time.Unix(1_000_000, 0)
	// A cookie minted while rolling was off: accepted until its own exp...
	old := IssuePassCookie(secret, DefaultPassPolicy(), "203.0.113.5", "", time.Time{}, now.Add(100*time.Second))
	pc, ok := VerifyPassCookie(secret, pol, old, "203.0.113.5", "", now)
	require.True(t, ok)
	// ...but never extended, whatever its age.
	_, renew := pol.Renewal(pc, now)
	require.False(t, renew)
	_, ok = VerifyPassCookie(secret, pol, old, "203.0.113.5", "", now.Add(101*time.Second))
	require.False(t, ok)
}

func TestVerifyEnforcesCurrentAbsoluteCap(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	issued := rollingPolicy() // idle 600s, max 4h
	iat := now.Add(-2 * time.Hour)
	c := IssuePassCookie(secret, issued, "203.0.113.5", "", iat, now.Add(300*time.Second))

	_, ok := VerifyPassCookie(secret, issued, c, "203.0.113.5", "", now)
	require.True(t, ok)

	// Operator lowers the cap to 1h: the 2h-old cookie is rejected before its exp.
	lowered := DefaultPassPolicy()
	lowered.MaxTTL = time.Hour
	_, ok = VerifyPassCookie(secret, lowered, c, "203.0.113.5", "", now)
	require.False(t, ok)

	// Exactly at the cap still passes; one second past does not.
	lowered.MaxTTL = 2 * time.Hour
	_, ok = VerifyPassCookie(secret, lowered, c, "203.0.113.5", "", now)
	require.True(t, ok)
	_, ok = VerifyPassCookie(secret, lowered, c, "203.0.113.5", "", now.Add(time.Second))
	require.False(t, ok)

	// With rolling off the cap check does not apply; the cookie lives to exp.
	_, ok = VerifyPassCookie(secret, DefaultPassPolicy(), c, "203.0.113.5", "", now)
	require.True(t, ok)
}

func TestInitialExp(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	require.Equal(t, now.Add(600*time.Second), DefaultPassPolicy().InitialExp(now.Add(-time.Hour), now), "non-rolling ignores issued-at")

	pol := DefaultPassPolicy()
	pol.MaxTTL = 700 * time.Second
	require.Equal(t, now.Add(600*time.Second), pol.InitialExp(now, now))
	require.Equal(t, now.Add(400*time.Second), pol.InitialExp(now.Add(-300*time.Second), now), "clamped to issued_at + max")
}

func TestPrefixWidths(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Minute)
	pol := DefaultPassPolicy()

	pol.IPv4Prefix = 32
	c := IssuePassCookie(secret, pol, "203.0.113.5", "", now, exp)
	require.Equal(t, "203.0.113.5/32", decodePayload(t, c)["p"])
	_, ok := VerifyPassCookie(secret, pol, c, "203.0.113.5", "", now)
	require.True(t, ok)
	_, ok = VerifyPassCookie(secret, pol, c, "203.0.113.6", "", now)
	require.False(t, ok)

	pol.IPv4Prefix = 16
	c = IssuePassCookie(secret, pol, "203.0.113.5", "", now, exp)
	require.Equal(t, "203.0.0.0/16", decodePayload(t, c)["p"])
	_, ok = VerifyPassCookie(secret, pol, c, "203.0.200.1", "", now)
	require.True(t, ok)
	_, ok = VerifyPassCookie(secret, pol, c, "203.1.0.1", "", now)
	require.False(t, ok)

	pol.IPv6Prefix = 48
	c = IssuePassCookie(secret, pol, "2001:db8:1:2::5", "", now, exp)
	require.Equal(t, "2001:db8:1::/48", decodePayload(t, c)["p"])
	_, ok = VerifyPassCookie(secret, pol, c, "2001:db8:1:ffff::1", "", now)
	require.True(t, ok)
	_, ok = VerifyPassCookie(secret, pol, c, "2001:db8:2::1", "", now)
	require.False(t, ok)

	pol.IPv6Prefix = 128
	c = IssuePassCookie(secret, pol, "2001:db8::5", "", now, exp)
	_, ok = VerifyPassCookie(secret, pol, c, "2001:db8::6", "", now)
	require.False(t, ok)

	// A default /24 cookie does not verify after an operator narrows to /32.
	def := IssueCookie(secret, "203.0.113.5", exp)
	pol = DefaultPassPolicy()
	pol.IPv4Prefix = 32
	_, ok = VerifyPassCookie(secret, pol, def, "203.0.113.5", "", now)
	require.False(t, ok)
}

func TestUserAgentBinding(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Minute)
	pol := DefaultPassPolicy()
	pol.BindUserAgent = true
	ua := "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"

	c := IssuePassCookie(secret, pol, "203.0.113.5", ua, now, exp)
	require.Len(t, decodePayload(t, c)["u"], 12)
	_, ok := VerifyPassCookie(secret, pol, c, "203.0.113.5", ua, now)
	require.True(t, ok)
	_, ok = VerifyPassCookie(secret, pol, c, "203.0.113.5", ua+" ", now)
	require.False(t, ok, "different UA must be rejected")
	_, ok = VerifyPassCookie(secret, pol, c, "203.0.113.5", "", now)
	require.False(t, ok, "missing UA must be rejected")

	// A cookie minted before binding was turned on has no UA hash: rejected.
	unbound := IssueCookie(secret, "203.0.113.5", exp)
	_, ok = VerifyPassCookie(secret, pol, unbound, "203.0.113.5", ua, now)
	require.False(t, ok)

	// Turning binding back off still accepts bound cookies.
	_, ok = VerifyPassCookie(secret, DefaultPassPolicy(), c, "203.0.113.5", "other", now)
	require.True(t, ok)

	// Empty UA hashes to a stable value, so a UA-less client can still pass.
	empty := IssuePassCookie(secret, pol, "203.0.113.5", "", now, exp)
	_, ok = VerifyPassCookie(secret, pol, empty, "203.0.113.5", "", now)
	require.True(t, ok)
}

func TestPassPolicyProvisionDefaults(t *testing.T) {
	a := &ChallengeApp{SecretCfg: "s"}
	require.NoError(t, a.Provision(caddy.Context{}))
	require.Equal(t, DefaultPassPolicy(), a.PassPolicy())
	require.Equal(t, PassPolicy{IdleTTL: 600 * time.Second, MaxTTL: 600 * time.Second, IPv4Prefix: 24, IPv6Prefix: 64}, a.PassPolicy())
}

func TestPassPolicyProvisionFromJSON(t *testing.T) {
	var a ChallengeApp
	require.NoError(t, json.Unmarshal([]byte(`{"secret":"s","pass_idle_ttl_seconds":900,"pass_max_ttl_seconds":14400,"pass_ipv4_prefix":28,"pass_ipv6_prefix":56,"pass_bind_user_agent":true}`), &a))
	require.NoError(t, a.Provision(caddy.Context{}))
	require.Equal(t, PassPolicy{IdleTTL: 900 * time.Second, MaxTTL: 4 * time.Hour, IPv4Prefix: 28, IPv6Prefix: 56, BindUserAgent: true}, a.PassPolicy())
	require.True(t, a.PassPolicy().Rolling())

	// Idle set, max unset: no rolling, max follows idle.
	b := ChallengeApp{SecretCfg: "s", PassIdleTTLSecondsCfg: 1200}
	require.NoError(t, b.Provision(caddy.Context{}))
	require.Equal(t, 1200*time.Second, b.PassPolicy().MaxTTL)
	require.False(t, b.PassPolicy().Rolling())
}

func TestPassPolicyProvisionValidation(t *testing.T) {
	cases := []struct {
		name string
		app  ChallengeApp
		msg  string
	}{
		{"negative idle", ChallengeApp{PassIdleTTLSecondsCfg: -1}, "pass_idle_ttl_seconds"},
		{"idle too short", ChallengeApp{PassIdleTTLSecondsCfg: 59}, "pass_idle_ttl_seconds"},
		{"idle too long", ChallengeApp{PassIdleTTLSecondsCfg: 86401}, "pass_idle_ttl_seconds"},
		{"negative max", ChallengeApp{PassMaxTTLSecondsCfg: -1}, "pass_max_ttl_seconds"},
		{"max below default idle", ChallengeApp{PassMaxTTLSecondsCfg: 300}, "pass_max_ttl_seconds"},
		{"max below idle", ChallengeApp{PassIdleTTLSecondsCfg: 900, PassMaxTTLSecondsCfg: 899}, "pass_max_ttl_seconds"},
		{"max too long", ChallengeApp{PassMaxTTLSecondsCfg: 604801}, "pass_max_ttl_seconds"},
		{"v4 too wide", ChallengeApp{PassIPv4PrefixCfg: 15}, "pass_ipv4_prefix"},
		{"v4 too long", ChallengeApp{PassIPv4PrefixCfg: 33}, "pass_ipv4_prefix"},
		{"v4 negative", ChallengeApp{PassIPv4PrefixCfg: -24}, "pass_ipv4_prefix"},
		{"v6 too wide", ChallengeApp{PassIPv6PrefixCfg: 31}, "pass_ipv6_prefix"},
		{"v6 too long", ChallengeApp{PassIPv6PrefixCfg: 129}, "pass_ipv6_prefix"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.app.SecretCfg = "s"
			err := tc.app.Provision(caddy.Context{})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.msg)
		})
	}

	// Boundaries are accepted.
	ok := ChallengeApp{SecretCfg: "s", PassIdleTTLSecondsCfg: 60, PassMaxTTLSecondsCfg: 604800, PassIPv4PrefixCfg: 16, PassIPv6PrefixCfg: 128}
	require.NoError(t, ok.Provision(caddy.Context{}))
	ok = ChallengeApp{SecretCfg: "s", PassIdleTTLSecondsCfg: 86400, PassMaxTTLSecondsCfg: 86400, PassIPv4PrefixCfg: 32, PassIPv6PrefixCfg: 32}
	require.NoError(t, ok.Provision(caddy.Context{}))
}

// policyApp is fakeApp with a configurable pass policy.
type policyApp struct {
	fakeApp
	pol    PassPolicy
	replay *NonceLRU
}

func (p policyApp) ReplayLRU() *NonceLRU { return p.replay }

func (p policyApp) PassPolicy() PassPolicy { return p.pol }

func policyHandler(pol PassPolicy) *ChallengeHandler {
	return &ChallengeHandler{app: policyApp{fakeApp: fakeApp{sec: "h-secret", diff: 8, vp: "/__apx_challenge/verify"}, pol: pol, replay: NewNonceLRU(1024)}}
}

func passCookieHeader(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName {
			return c
		}
	}
	return nil
}

func TestHandlerDefaultPolicyDoesNotRenew(t *testing.T) {
	h := policyHandler(DefaultPassPolicy())
	now := time.Now()
	r := browserReq("/page")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: IssueCookie("h-secret", "203.0.113.5", now.Add(10*time.Second))})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Equal(t, "UPSTREAM", w.Body.String())
	require.Empty(t, w.Header().Values("Set-Cookie"))
}

func TestHandlerRollingRenewsWhenDue(t *testing.T) {
	pol := rollingPolicy()
	h := policyHandler(pol)
	now := time.Now()

	// More than half the idle TTL left: no Set-Cookie.
	r := browserReq("/page")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: IssuePassCookie("h-secret", pol, "203.0.113.5", "", now, now.Add(500*time.Second))})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Equal(t, "UPSTREAM", w.Body.String())
	require.Empty(t, w.Header().Values("Set-Cookie"))

	// Under half left: renewed with full attributes and Max-Age == new exp - now.
	iat := now.Add(-time.Hour)
	r = browserReq("/page")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: IssuePassCookie("h-secret", pol, "203.0.113.5", "", iat, now.Add(60*time.Second))})
	w = httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Equal(t, "UPSTREAM", w.Body.String())
	sc := w.Header().Get("Set-Cookie")
	require.Contains(t, sc, "Path=/")
	require.Contains(t, sc, "HttpOnly")
	require.Contains(t, sc, "Secure")
	require.Contains(t, sc, "SameSite=Lax")
	c := passCookieHeader(t, w)
	require.NotNil(t, c)
	pc, ok := VerifyPassCookie("h-secret", pol, c.Value, "203.0.113.5", "", time.Now())
	require.True(t, ok)
	require.Equal(t, iat.Unix(), pc.IssuedAt.Unix())
	require.InDelta(t, 600, c.MaxAge, 1)
	require.InDelta(t, pc.Exp.Unix()-now.Unix(), c.MaxAge, 1)
}

func TestHandlerRollingStopsAtCap(t *testing.T) {
	pol := rollingPolicy()
	h := policyHandler(pol)
	now := time.Now()
	iat := now.Add(-4*time.Hour + 30*time.Second)
	r := browserReq("/page")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: IssuePassCookie("h-secret", pol, "203.0.113.5", "", iat, iat.Add(4*time.Hour))})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Equal(t, "UPSTREAM", w.Body.String())
	require.Empty(t, w.Header().Values("Set-Cookie"))
}

func TestHandlerUserAgentBinding(t *testing.T) {
	pol := DefaultPassPolicy()
	pol.BindUserAgent = true
	h := policyHandler(pol)
	now := time.Now()
	val := IssuePassCookie("h-secret", pol, "203.0.113.5", "UA-1", now, now.Add(time.Minute))

	r := browserReq("/page")
	r.Header.Set("User-Agent", "UA-1")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: val})
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.Equal(t, "UPSTREAM", w.Body.String())

	r = browserReq("/page")
	r.Header.Set("User-Agent", "UA-2")
	r.AddCookie(&http.Cookie{Name: CookieName, Value: val})
	w = httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	require.NotEqual(t, "UPSTREAM", w.Body.String(), "a cookie replayed under another UA is re-challenged")
}

func TestHandleVerifyIssuesPolicyCookie(t *testing.T) {
	pol := rollingPolicy()
	pol.IdleTTL = 900 * time.Second
	pol.BindUserAgent = true
	h := policyHandler(pol)
	// Token issued 2 minutes before the solve is posted.
	tokExp := time.Now().Add(challengeTokenTTL - 2*time.Minute)
	tok := IssuePassChallenge("h-secret", pol, "203.0.113.5", "UA-1", "/x", tokExp)

	w := postVerify(t, h, tok, "203.0.113.5", "UA-1")
	require.Equal(t, http.StatusSeeOther, w.Code)
	c := passCookieHeader(t, w)
	require.NotNil(t, c)
	require.InDelta(t, 900, c.MaxAge, 1)
	require.Equal(t, float64(tokExp.Unix()-int64(challengeTokenTTL/time.Second)), decodePayload(t, c.Value)["i"], "issued-at is the challenge's issue time")
	require.True(t, c.HttpOnly)
	require.True(t, c.Secure)
	require.Equal(t, http.SameSiteLaxMode, c.SameSite)
	require.Equal(t, "/", c.Path)
	p := decodePayload(t, c.Value)
	require.Contains(t, p, "i")
	require.Contains(t, p, "u")
	_, ok := VerifyPassCookie("h-secret", pol, c.Value, "203.0.113.5", "UA-1", time.Now())
	require.True(t, ok)
}

func postVerify(t *testing.T, h *ChallengeHandler, tok, ip, ua string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"challenge": {tok}, "solution": {SolvePoW(tok, 8)}}
	r := httptest.NewRequest("POST", "/__apx_challenge/verify", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", ua)
	r.RemoteAddr = ip + ":443"
	r = withVars(r)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	return w
}

func TestChallengeTokenBindsPolicyPrefixAndUA(t *testing.T) {
	pol := DefaultPassPolicy()
	pol.IPv4Prefix = 32
	pol.BindUserAgent = true
	now := time.Now()
	tok := IssuePassChallenge(secret, pol, "203.0.113.5", "UA-1", "/x", now.Add(time.Minute))
	require.Equal(t, "203.0.113.5/32", decodePayload(t, tok)["p"])

	_, err := VerifyPassChallenge(secret, pol, tok, "203.0.113.5", "UA-1", now)
	require.NoError(t, err)
	_, err = VerifyPassChallenge(secret, pol, tok, "203.0.113.6", "UA-1", now)
	require.Error(t, err, "another address in the /24 can't use a /32 token")
	_, err = VerifyPassChallenge(secret, pol, tok, "203.0.113.5", "UA-2", now)
	require.Error(t, err, "another UA can't use a UA-bound token")

	// A default (/24, no UA) token is rejected under the tighter policy.
	_, err = VerifyPassChallenge(secret, pol, IssueChallenge(secret, "203.0.113.5", "/x", now.Add(time.Minute)), "203.0.113.5", "UA-1", now)
	require.Error(t, err)
}

func TestOneSolveMintsOneCookieUnderPolicy(t *testing.T) {
	pol := DefaultPassPolicy()
	pol.IPv4Prefix = 32
	pol.BindUserAgent = true
	h := policyHandler(pol)
	tok := IssuePassChallenge("h-secret", pol, "203.0.113.5", "UA-1", "/x", time.Now().Add(challengeTokenTTL))

	require.Equal(t, http.StatusSeeOther, postVerify(t, h, tok, "203.0.113.5", "UA-1").Code)
	for _, c := range []struct{ ip, ua string }{
		{"203.0.113.5", "UA-1"}, // straight replay
		{"203.0.113.6", "UA-1"}, // other address
		{"203.0.113.5", "UA-2"}, // other UA
	} {
		w := postVerify(t, h, tok, c.ip, c.ua)
		require.Equal(t, http.StatusForbidden, w.Code, "%+v", c)
		require.Nil(t, passCookieHeader(t, w), "%+v", c)
	}
}

func TestRollingSolveIsSingleUse(t *testing.T) {
	// Rolling only (/24, no UA): binding alone would let a second address in the
	// /24 replay the solve and reset the cap; single-use stops it.
	h := policyHandler(rollingPolicy())
	tok := IssueChallenge("h-secret", "203.0.113.5", "/x", time.Now().Add(challengeTokenTTL))
	require.Equal(t, http.StatusSeeOther, postVerify(t, h, tok, "203.0.113.5", "UA").Code)
	w := postVerify(t, h, tok, "203.0.113.6", "UA")
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Nil(t, passCookieHeader(t, w))
}

func TestDefaultPolicyVerifyStaysReusable(t *testing.T) {
	h := policyHandler(DefaultPassPolicy())
	tok := IssueChallenge("h-secret", "203.0.113.5", "/x", time.Now().Add(challengeTokenTTL))
	for i := 0; i < 2; i++ {
		w := postVerify(t, h, tok, "203.0.113.5", "UA")
		require.Equal(t, http.StatusSeeOther, w.Code, "default behaviour is unchanged: no single-use")
		require.NotNil(t, passCookieHeader(t, w))
	}
}

func TestHandleVerifyDefaultCookieShape(t *testing.T) {
	h := policyHandler(DefaultPassPolicy())
	tok := IssueChallenge("h-secret", "203.0.113.5", "/x", time.Now().Add(time.Minute))
	sol := SolvePoW(tok, 8)

	r := httptest.NewRequest("POST", "/__apx_challenge/verify", strings.NewReader("challenge="+tok+"&solution="+sol))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "UA-1")
	r.RemoteAddr = "203.0.113.5:443"
	r = withVars(r)
	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, r, nextOK))
	c := passCookieHeader(t, w)
	require.NotNil(t, c)
	require.Equal(t, 600, c.MaxAge)
	p := decodePayload(t, c.Value)
	require.Len(t, p, 2, "default cookie payload is exactly {e, p}")
	require.Equal(t, "203.0.113.0/24", p["p"])
	require.True(t, legacyVerifyCookie("h-secret", c.Value, "203.0.113.5"))
}

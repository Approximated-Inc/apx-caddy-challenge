package apxchallenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"
)

// CookieName is the pass cookie set after a solved challenge.
const CookieName = "apx-challenge"

// Domain-separation labels mixed into the HMAC input so a challenge token can
// never validate as a pass cookie (and vice versa).
const (
	challengeDomain = "chal"
	cookieDomain    = "pass"
)

// ChallengePayload is the signed body of an issued PoW challenge token.
type ChallengePayload struct {
	Exp    int64  `json:"e"`
	Nonce  string `json:"n"`
	Prefix string `json:"p"`
	Ret    string `json:"r"`
}

// cookiePayload is the signed pass-cookie body. Iat and UA are omitted unless
// the policy uses them, so a default-policy cookie is byte-identical to the
// original {e, p} shape.
type cookiePayload struct {
	Exp    int64  `json:"e"`
	Prefix string `json:"p"`
	Iat    int64  `json:"i,omitempty"`
	UA     string `json:"u,omitempty"`
}

// legacyPassTTL is the fixed lifetime of cookies minted without an issued-at,
// used to infer their issue time (exp - 600s) for the absolute cap.
const legacyPassTTL = 600 * time.Second

// PassPolicy controls pass-cookie lifetime and binding. DefaultPassPolicy is
// the original behaviour.
type PassPolicy struct {
	// IdleTTL is the cookie lifetime from issue or last renewal.
	IdleTTL time.Duration
	// MaxTTL caps the lifetime from the original solve. Rolling renewal is on
	// only when MaxTTL > IdleTTL.
	MaxTTL        time.Duration
	IPv4Prefix    int
	IPv6Prefix    int
	BindUserAgent bool
}

// DefaultPassPolicy: 10-minute non-rolling cookie bound to the /24 or /64.
func DefaultPassPolicy() PassPolicy {
	return PassPolicy{IdleTTL: cookieTTL, MaxTTL: cookieTTL, IPv4Prefix: 24, IPv6Prefix: 64}
}

// Rolling reports whether valid cookies are renewed while in use.
func (pol PassPolicy) Rolling() bool { return pol.MaxTTL > pol.IdleTTL }

// PassCookie is a verified pass cookie's lifetime.
type PassCookie struct {
	Exp      time.Time
	IssuedAt time.Time
}

// Renewal returns the new expiry for a valid cookie when rolling renewal is on
// and less than half the idle TTL remains: min(now + idle, issued_at + max).
// False when renewal is off, not yet due, or the absolute cap is reached.
func (pol PassPolicy) Renewal(c PassCookie, now time.Time) (time.Time, bool) {
	if !pol.Rolling() || c.Exp.Sub(now) >= pol.IdleTTL/2 {
		return time.Time{}, false
	}
	exp := now.Add(pol.IdleTTL)
	if capAt := c.IssuedAt.Add(pol.MaxTTL); capAt.Before(exp) {
		exp = capAt
	}
	exp = time.Unix(exp.Unix(), 0)
	if !exp.After(c.Exp) {
		return time.Time{}, false
	}
	return exp, true
}

var errInvalid = errors.New("apx_challenge: invalid or expired token")

// clientPrefix returns the /24 (v4) or /64 (v6) network of ip as a string.
// The bool is false when ip is unparseable, so callers can reject rather than
// match unparseable IPs against each other.
func clientPrefix(ip string) (string, bool) {
	return clientPrefixWidth(ip, 24, 64)
}

// clientPrefixWidth is clientPrefix with explicit v4 / v6 prefix lengths.
func clientPrefixWidth(ip string, v4Bits, v6Bits int) (string, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	if v4 := parsed.To4(); v4 != nil {
		mask := net.CIDRMask(v4Bits, 32)
		return (&net.IPNet{IP: v4.Mask(mask), Mask: mask}).String(), true
	}
	mask := net.CIDRMask(v6Bits, 128)
	return (&net.IPNet{IP: parsed.Mask(mask), Mask: mask}).String(), true
}

// uaHash is a short, unkeyed digest of the User-Agent. It sits inside the
// HMAC-signed payload, so it needs no key, only stability.
func uaHash(ua string) string {
	sum := sha256.Sum256([]byte(ua))
	return base64.RawURLEncoding.EncodeToString(sum[:9])
}

func sign(secret, domain string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(domain))
	m.Write([]byte{0}) // unambiguous separator between domain and body
	m.Write(body)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func encodeSigned(secret, domain string, body []byte) string {
	return base64.RawURLEncoding.EncodeToString(body) + "." + sign(secret, domain, body)
}

// splitVerify returns the decoded body iff the signature matches (constant-time).
func splitVerify(secret, domain, token string) ([]byte, error) {
	dot := -1
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			dot = i
			break
		}
	}
	if dot <= 0 {
		return nil, errInvalid
	}
	body, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return nil, errInvalid
	}
	want := sign(secret, domain, body)
	if !hmac.Equal([]byte(want), []byte(token[dot+1:])) {
		return nil, errInvalid
	}
	return body, nil
}

// IssueChallenge mints a signed PoW challenge token bound to the client prefix.
func IssueChallenge(secret, ip, ret string, exp time.Time) string {
	nb := make([]byte, 12)
	_, _ = rand.Read(nb)
	pref, _ := clientPrefix(ip)
	body, _ := json.Marshal(ChallengePayload{
		Exp:    exp.Unix(),
		Nonce:  base64.RawURLEncoding.EncodeToString(nb),
		Prefix: pref,
		Ret:    ret,
	})
	return encodeSigned(secret, challengeDomain, body)
}

// VerifyChallenge checks signature, expiry, and prefix match.
func VerifyChallenge(secret, token, ip string) (ChallengePayload, error) {
	body, err := splitVerify(secret, challengeDomain, token)
	if err != nil {
		return ChallengePayload{}, err
	}
	var p ChallengePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return ChallengePayload{}, errInvalid
	}
	if time.Now().Unix() > p.Exp {
		return ChallengePayload{}, errInvalid
	}
	pref, ok := clientPrefix(ip)
	if !ok || p.Prefix != pref {
		return ChallengePayload{}, errInvalid
	}
	return p, nil
}

// IssueCookie mints a default-policy pass cookie value (HMAC over {exp, prefix}).
func IssueCookie(secret, ip string, exp time.Time) string {
	return IssuePassCookie(secret, DefaultPassPolicy(), ip, "", time.Time{}, exp)
}

// VerifyCookie reports whether the cookie is well-signed, unexpired, and bound
// to the requester's current prefix under the default policy.
func VerifyCookie(secret, cookie, ip string) bool {
	_, ok := VerifyPassCookie(secret, DefaultPassPolicy(), cookie, ip, "", time.Now())
	return ok
}

// IssuePassCookie mints a pass cookie under pol. issuedAt is recorded only
// when pol is rolling, and the UA hash only when pol binds the User-Agent.
func IssuePassCookie(secret string, pol PassPolicy, ip, ua string, issuedAt, exp time.Time) string {
	pref, _ := clientPrefixWidth(ip, pol.IPv4Prefix, pol.IPv6Prefix)
	p := cookiePayload{Exp: exp.Unix(), Prefix: pref}
	if pol.Rolling() {
		p.Iat = issuedAt.Unix()
	}
	if pol.BindUserAgent {
		p.UA = uaHash(ua)
	}
	body, _ := json.Marshal(p)
	return encodeSigned(secret, cookieDomain, body)
}

// VerifyPassCookie checks signature, expiry, prefix binding under pol and,
// when pol binds the User-Agent, the UA hash. A cookie without an issued-at is
// treated as issued at exp - 600s.
func VerifyPassCookie(secret string, pol PassPolicy, cookie, ip, ua string, now time.Time) (PassCookie, bool) {
	body, err := splitVerify(secret, cookieDomain, cookie)
	if err != nil {
		return PassCookie{}, false
	}
	var p cookiePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return PassCookie{}, false
	}
	if now.Unix() > p.Exp {
		return PassCookie{}, false
	}
	pref, ok := clientPrefixWidth(ip, pol.IPv4Prefix, pol.IPv6Prefix)
	if !ok || p.Prefix != pref {
		return PassCookie{}, false
	}
	if pol.BindUserAgent && !hmac.Equal([]byte(p.UA), []byte(uaHash(ua))) {
		return PassCookie{}, false
	}
	exp := time.Unix(p.Exp, 0)
	iat := exp.Add(-legacyPassTTL)
	if p.Iat != 0 {
		iat = time.Unix(p.Iat, 0)
	}
	return PassCookie{Exp: exp, IssuedAt: iat}, true
}

// setPassCookie writes the pass cookie with Max-Age matching exp.
func setPassCookie(w http.ResponseWriter, value string, exp, now time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(exp.Unix() - now.Unix()),
	})
}

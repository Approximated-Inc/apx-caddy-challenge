package apxchallenge

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"
)

// New HMAC domains, distinct from chal/pass in cookie.go so a verify
// challenge/token can never cross-validate as an interstitial token.
const (
	verifyChallengeDomain = "verifychal"
	verifyTokenDomain     = "verifytok"
)

// VerifyChallengePayload is the signed body of an issued Edge Verify PoW challenge.
type VerifyChallengePayload struct {
	Exp    int64  `json:"e"`
	Nonce  string `json:"n"`
	Prefix string `json:"p"`
	Diff   int    `json:"d"`
}

// VerifyTokenPayload is the signed body of a minted Edge Verify token.
type VerifyTokenPayload struct {
	Exp    int64  `json:"e"`
	Nonce  string `json:"n"`
	Prefix string `json:"p"`
	Host   string `json:"h"`
}

func randNonce() string {
	nb := make([]byte, 12)
	_, _ = rand.Read(nb)
	return base64.RawURLEncoding.EncodeToString(nb)
}

// IssueVerifyChallenge mints a signed PoW challenge bound to the client prefix,
// carrying the difficulty the widget must solve.
func IssueVerifyChallenge(secret, ip string, difficulty int, exp time.Time) string {
	pref, _ := clientPrefix(ip)
	body, _ := json.Marshal(VerifyChallengePayload{
		Exp: exp.Unix(), Nonce: randNonce(), Prefix: pref, Diff: difficulty,
	})
	return encodeSigned(secret, verifyChallengeDomain, body)
}

// CheckVerifyChallenge checks signature, expiry, and prefix match.
func CheckVerifyChallenge(secret, token, ip string) (VerifyChallengePayload, error) {
	body, err := splitVerify(secret, verifyChallengeDomain, token)
	if err != nil {
		return VerifyChallengePayload{}, err
	}
	var p VerifyChallengePayload
	if err := json.Unmarshal(body, &p); err != nil {
		return VerifyChallengePayload{}, errInvalid
	}
	if time.Now().Unix() > p.Exp {
		return VerifyChallengePayload{}, errInvalid
	}
	pref, ok := clientPrefix(ip)
	if !ok || p.Prefix != pref {
		return VerifyChallengePayload{}, errInvalid
	}
	return p, nil
}

// IssueVerifyToken mints the token the widget injects into the form. Bound to
// client prefix AND host so a token minted for one site can't clear another.
func IssueVerifyToken(secret, ip, host, nonce string, exp time.Time) string {
	pref, _ := clientPrefix(ip)
	body, _ := json.Marshal(VerifyTokenPayload{
		Exp: exp.Unix(), Nonce: nonce, Prefix: pref, Host: host,
	})
	return encodeSigned(secret, verifyTokenDomain, body)
}

// CheckVerifyToken checks signature, expiry, prefix, and host.
func CheckVerifyToken(secret, token, ip, host string) (VerifyTokenPayload, error) {
	body, err := splitVerify(secret, verifyTokenDomain, token)
	if err != nil {
		return VerifyTokenPayload{}, err
	}
	var p VerifyTokenPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return VerifyTokenPayload{}, errInvalid
	}
	if time.Now().Unix() > p.Exp {
		return VerifyTokenPayload{}, errInvalid
	}
	pref, ok := clientPrefix(ip)
	if !ok || p.Prefix != pref || p.Host != host {
		return VerifyTokenPayload{}, errInvalid
	}
	return p, nil
}

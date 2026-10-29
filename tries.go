package apxchallenge

import (
	"encoding/json"
	"net/http"
	"time"
)

// The tries cookie is the challenge loop breaker. It counts recent failed and
// passed verifies; at maxVerifyTries of either kind the visitor gets an
// explanation page instead of another challenge. Passes count because a
// browser that never stores or sends the pass cookie loops on success. It is
// cleared only when a request presents a valid pass cookie.
//
// The __Host- prefix makes browsers refuse a copy planted from a parent
// domain or over plain http (Secure, Path=/, no Domain), and the value is
// HMAC-signed under its own domain label, so an unsigned or forged value
// counts as zero. It is not bound to the client prefix: a visitor whose /24
// alternates between verifies must keep its count.
const (
	triesCookieName = "__Host-apx-challenge-tries"
	triesDomain     = "tries"
	maxVerifyTries  = 3

	// Covers several 5-minute tokens plus slow solves, so a solve that takes
	// longer than a few minutes still counts as the next attempt.
	triesCookieTTL = 30 * time.Minute

	// A pass counts only when the previous counted pass is at least
	// passCountSpacing old (several tabs solving at once, or Retry during an
	// in-flight verify, are one pass), and the run restarts when it is more
	// than passCountWindow old (ordinary re-challenges after the pass cookie
	// expires, including on machines that don't clear the counter). A real
	// success loop takes a second or two per round, so three counted passes
	// mean it has looped for at least 30 s. A pass inside the spacing gets the
	// "Continuing…" page instead of a 303, so a loop slows to one solve per
	// continueDelay while it waits.
	passCountSpacing = 15 * time.Second
	passCountWindow  = 5 * time.Minute
	continueDelay    = 5 * time.Second
)

type triesState struct {
	Failed   int   `json:"f"`
	Passed   int   `json:"p"`
	LastPass int64 `json:"t,omitempty"` // unix seconds of the last counted pass
}

func (s *triesState) countFailure() {
	s.Failed = min(s.Failed+1, maxVerifyTries)
}

// countPass records a pass and reports whether it counted (false: too soon
// after the last counted pass, the same round).
func (s *triesState) countPass(now time.Time) bool {
	age := now.Sub(time.Unix(s.LastPass, 0))
	switch {
	case s.LastPass == 0 || s.Passed == 0 || age > passCountWindow || age < 0:
		s.Passed = 1
	case age >= passCountSpacing:
		s.Passed = min(s.Passed+1, maxVerifyTries)
	default:
		return false
	}
	s.LastPass = now.Unix()
	return true
}

// readTries returns the request's counter, or zero when it is missing,
// unsigned or forged.
func readTries(r *http.Request, secret string) triesState {
	c, err := r.Cookie(triesCookieName)
	if err != nil {
		return triesState{}
	}
	body, err := splitVerify(secret, triesDomain, c.Value)
	if err != nil {
		return triesState{}
	}
	var s triesState
	if json.Unmarshal(body, &s) != nil {
		return triesState{}
	}
	// Clamp before counting: MaxInt + 1 would wrap negative and loop again.
	s.Failed = min(max(s.Failed, 0), maxVerifyTries)
	s.Passed = min(max(s.Passed, 0), maxVerifyTries)
	return s
}

func writeTries(w http.ResponseWriter, secret string, s triesState) {
	body, _ := json.Marshal(s)
	http.SetCookie(w, &http.Cookie{
		Name:     triesCookieName,
		Value:    encodeSigned(secret, triesDomain, body),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(triesCookieTTL.Seconds()),
	})
}

// clearTriesCookie expires the counter once a request presents a valid pass
// cookie. Only sent when the request carried one.
func clearTriesCookie(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(triesCookieName); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     triesCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

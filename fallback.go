package apxchallenge

import (
	"container/heap"
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The render-check fallback lets a browser that can't run the proof-of-work
// script pass without JavaScript. It proves browser-like behaviour, not a
// human: the visitor must keep a cookie from the challenge response, render
// the page's inline CSS (which loads a signed 1x1 image on this machine), wait
// at least the minimum dwell, and post the fallback form once. Simple HTTP
// clients do none of that.
//
// Rendered and spent nonces, and the per-prefix pass budget, are per machine.
// A pixel or POST that lands on another machine finds nothing recorded there
// and takes the ordinary failure path (a fresh challenge); state is never
// shared across the cluster.
const (
	fallbackDomain       = "fallback"
	fallbackCookieDomain = "fallback-cookie"
	fallbackPixelDomain  = "fallback-pixel"

	fallbackCookieName = "__Host-apx-challenge-fallback"
	fallbackPixelParam = "apx_fallback_pixel"
	fallbackModeValue  = "fallback"

	// fallbackTokenTTL bounds the form token and its cookie. A visitor reads
	// the page, or waits for the failure panel, well within it.
	fallbackTokenTTL = 10 * time.Minute

	fallbackRateWindow = time.Hour

	defaultFallbackPassTTLSeconds  = 300
	defaultFallbackMaxPerHour      = 3
	defaultFallbackMinDwellSeconds = 2
	minFallbackPassTTLSeconds      = 60
	maxFallbackPassTTLSeconds      = 86400
	maxFallbackMaxPerHour          = 1000
	maxFallbackMinDwellSeconds     = 60

	fallbackNonceEncodedLen = 16 // base64url of the 12-byte nonce
	// fallbackCookieNonces is how many recent nonces the fallback cookie keeps.
	fallbackCookieNonces = 4
)

// FallbackConfig is the render-check fallback configuration (fallback_* keys).
// The zero value is off.
type FallbackConfig struct {
	Enabled    bool
	PassTTL    time.Duration
	MaxPerHour int
	MinDwell   time.Duration
}

// buildFallbackConfig validates the fallback_* keys. Zero values take the
// defaults; out-of-range values fail provisioning. The fallback cookie is never
// longer-lived than a solved one: an explicit fallback_pass_ttl_seconds above
// passIdleTTL is an error, and the default is clamped to passIdleTTL.
func buildFallbackConfig(enabled bool, passTTLS, maxPerHour, minDwellS int, passIdleTTL time.Duration) (FallbackConfig, error) {
	fb := FallbackConfig{
		Enabled:    enabled,
		PassTTL:    min(defaultFallbackPassTTLSeconds*time.Second, passIdleTTL),
		MaxPerHour: defaultFallbackMaxPerHour,
		MinDwell:   defaultFallbackMinDwellSeconds * time.Second,
	}
	switch {
	case passTTLS < 0, passTTLS > 0 && (passTTLS < minFallbackPassTTLSeconds || passTTLS > maxFallbackPassTTLSeconds):
		return fb, fmt.Errorf("apx_challenge app: fallback_pass_ttl_seconds must be %d-%d (got %d)", minFallbackPassTTLSeconds, maxFallbackPassTTLSeconds, passTTLS)
	case passTTLS > 0 && time.Duration(passTTLS)*time.Second > passIdleTTL:
		return fb, fmt.Errorf("apx_challenge app: fallback_pass_ttl_seconds (%d) must not exceed the pass idle TTL (%d)", passTTLS, int(passIdleTTL.Seconds()))
	case passTTLS > 0:
		fb.PassTTL = time.Duration(passTTLS) * time.Second
	}
	switch {
	case maxPerHour < 0 || maxPerHour > maxFallbackMaxPerHour:
		return fb, fmt.Errorf("apx_challenge app: fallback_max_per_hour must be 1-%d (got %d)", maxFallbackMaxPerHour, maxPerHour)
	case maxPerHour > 0:
		fb.MaxPerHour = maxPerHour
	}
	switch {
	case minDwellS < 0 || minDwellS > maxFallbackMinDwellSeconds:
		return fb, fmt.Errorf("apx_challenge app: fallback_min_dwell_seconds must be 1-%d (got %d)", maxFallbackMinDwellSeconds, minDwellS)
	case minDwellS > 0:
		fb.MinDwell = time.Duration(minDwellS) * time.Second
	}
	return fb, nil
}

// FallbackState is the per-machine memory the fallback needs: nonces whose
// pixel was fetched here, nonces spent by a pass, and recent fallback passes
// per client prefix. It is separate from the replay LRU Edge Verify and the
// solve path share, so fallback traffic can never evict their entries.
type FallbackState struct {
	Rendered *ExpiringSet
	Spent    *ExpiringSet
	Limiter  *FallbackLimiter
}

// NewFallbackState returns empty stores bounded to size entries each.
func NewFallbackState(size int) *FallbackState {
	return &FallbackState{Rendered: NewExpiringSet(size), Spent: NewExpiringSet(size), Limiter: NewFallbackLimiter(size)}
}

// processFallbackState lives at package level for the same reason as
// processReplayLRU: a config reload must not forget rendered nonces or reset
// the pass budget.
var processFallbackState = NewFallbackState(fallbackStoreSize)

// fallbackStoreSize bounds each fallback store. Records live for the token's
// 10 minutes, so this is the live window, not history (all three stores
// full measured about 6.5 MB). See the README for the eviction bound.
const fallbackStoreSize = 16384

// fallbackPayload is the signed body of a fallback form token.
type fallbackPayload struct {
	Exp    int64  `json:"e"` // unix seconds
	Iat    int64  `json:"i"` // unix milliseconds, for the dwell check
	Nonce  string `json:"n"`
	Prefix string `json:"p"`
	Ret    string `json:"r"`
	UA     string `json:"u,omitempty"`
}

// issueFallbackToken mints a fallback form token bound to the pass policy's
// prefix width (and UA hash under UA binding), and returns it with its nonce.
func issueFallbackToken(secret string, pol PassPolicy, ip, ua, ret string, now time.Time) (string, string) {
	nb := make([]byte, 12)
	_, _ = rand.Read(nb)
	nonce := base64.RawURLEncoding.EncodeToString(nb)
	return issueFallbackTokenNonce(secret, pol, ip, ua, ret, now, nonce), nonce
}

func issueFallbackTokenNonce(secret string, pol PassPolicy, ip, ua, ret string, now time.Time, nonce string) string {
	pref, _ := clientPrefixWidth(ip, pol.IPv4Prefix, pol.IPv6Prefix)
	p := fallbackPayload{
		Exp:    now.Add(fallbackTokenTTL).Unix(),
		Iat:    now.UnixMilli(),
		Nonce:  nonce,
		Prefix: pref,
		Ret:    ret,
	}
	if pol.BindUserAgent {
		p.UA = uaHash(ua)
	}
	body, _ := json.Marshal(p)
	return encodeSigned(secret, fallbackDomain, body)
}

// verifyFallbackToken checks signature, expiry, the prefix under pol and,
// when pol binds the User-Agent, the UA hash.
func verifyFallbackToken(secret string, pol PassPolicy, token, ip, ua string, now time.Time) (fallbackPayload, error) {
	body, err := splitVerify(secret, fallbackDomain, token)
	if err != nil {
		return fallbackPayload{}, err
	}
	var p fallbackPayload
	if json.Unmarshal(body, &p) != nil || p.Nonce == "" {
		return fallbackPayload{}, errInvalid
	}
	if now.Unix() > p.Exp {
		return fallbackPayload{}, errInvalid
	}
	pref, ok := clientPrefixWidth(ip, pol.IPv4Prefix, pol.IPv6Prefix)
	if !ok || p.Prefix != pref {
		return fallbackPayload{}, errInvalid
	}
	if pol.BindUserAgent && !hmac.Equal([]byte(p.UA), []byte(uaHash(ua))) {
		return fallbackPayload{}, errInvalid
	}
	return p, nil
}

// setFallbackCookie sets the cookie a fallback POST must carry back. It holds
// the most recent fallbackCookieNonces nonces, newest first, so a second tab
// or a stray challenged subresource doesn't strand the page being read.
func setFallbackCookie(w http.ResponseWriter, secret string, nonces []string) {
	if len(nonces) == 0 {
		clearFallbackCookie(w)
		return
	}
	body, _ := json.Marshal(nonces)
	http.SetCookie(w, &http.Cookie{
		Name:     fallbackCookieName,
		Value:    encodeSigned(secret, fallbackCookieDomain, body),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(fallbackTokenTTL.Seconds()),
	})
}

func clearFallbackCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     fallbackCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// readFallbackNonces returns the nonces in r's fallback cookie, or nil when
// it is missing, unsigned or forged.
func readFallbackNonces(r *http.Request, secret string) []string {
	c, err := r.Cookie(fallbackCookieName)
	if err != nil {
		return nil
	}
	body, err := splitVerify(secret, fallbackCookieDomain, c.Value)
	if err != nil {
		return nil
	}
	var ns []string
	if json.Unmarshal(body, &ns) != nil {
		return nil
	}
	if len(ns) > fallbackCookieNonces {
		ns = ns[:fallbackCookieNonces]
	}
	return ns
}

// withNonce returns ns with nonce first, deduplicated, at most
// fallbackCookieNonces long.
func withNonce(ns []string, nonce string) []string {
	out := []string{nonce}
	for _, n := range ns {
		if n != nonce && len(out) < fallbackCookieNonces {
			out = append(out, n)
		}
	}
	return out
}

// withoutNonce returns ns without nonce.
func withoutNonce(ns []string, nonce string) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		if n != nonce {
			out = append(out, n)
		}
	}
	return out
}

// fallbackCookieMatches reports whether r carries a well-signed fallback
// cookie listing nonce.
func fallbackCookieMatches(r *http.Request, secret, nonce string) bool {
	for _, n := range readFallbackNonces(r, secret) {
		if hmac.Equal([]byte(n), []byte(nonce)) {
			return true
		}
	}
	return false
}

// isLikelyDocument reports whether a challenged request is probably a page
// the visitor will see, not a subresource such as /favicon.ico (old browsers
// send those with Accept: */* and no Sec-Fetch headers). Only those get the
// fallback form and a fallback cookie update.
func isLikelyDocument(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Dest") == "document" || strings.Contains(r.Header.Get("Accept"), "text/html")
}

// fallbackPixelURL is the signed image URL the page's CSS loads. It sits on
// the verify path (as a query) so the existing verify route reaches it. The
// signature covers the nonce, the token's expiry and the requester's prefix
// (and UA hash under UA binding), so an archived URL dies with its token and
// works only from the network that fetched the page.
func fallbackPixelURL(secret, verifyPath string, pol PassPolicy, ip, ua, nonce string, exp int64) string {
	e := strconv.FormatInt(exp, 10)
	return verifyPath + "?" + fallbackPixelParam + "=" + nonce + "." + e + "." + fallbackPixelSig(secret, pol, ip, ua, nonce, e)
}

func fallbackPixelSig(secret string, pol PassPolicy, ip, ua, nonce, exp string) string {
	pref, _ := clientPrefixWidth(ip, pol.IPv4Prefix, pol.IPv6Prefix)
	uah := ""
	if pol.BindUserAgent {
		uah = uaHash(ua)
	}
	return sign(secret, fallbackPixelDomain, []byte(nonce+"|"+exp+"|"+pref+"|"+uah))
}

// verifyFallbackPixel returns the nonce and expiry of a pixel value signed
// for this requester and not yet expired.
func verifyFallbackPixel(secret string, pol PassPolicy, ip, ua, v string, now time.Time) (string, time.Time, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || len(parts[0]) != fallbackNonceEncodedLen {
		return "", time.Time{}, false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || now.Unix() > exp {
		return "", time.Time{}, false
	}
	if _, ok := clientPrefixWidth(ip, pol.IPv4Prefix, pol.IPv6Prefix); !ok {
		return "", time.Time{}, false
	}
	if !hmac.Equal([]byte(parts[2]), []byte(fallbackPixelSig(secret, pol, ip, ua, parts[0], parts[1]))) {
		return "", time.Time{}, false
	}
	return parts[0], time.Unix(exp, 0), true
}

// transparentGIF is a 1x1 transparent GIF.
var transparentGIF = []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")

// isFallbackPixelRequest reports whether r is a GET or HEAD for the pixel.
func isFallbackPixelRequest(r *http.Request, verifyPath string) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return r.URL.Path == verifyPath && r.URL.Query().Has(fallbackPixelParam)
}

// isImageLoad reports whether a pixel request looks like a browser loading an
// image: a GET with Sec-Fetch-Dest: image when any Sec-Fetch header is sent,
// or, from browsers without Sec-Fetch, an Accept header naming an image type.
// Anything else still gets the image but is not recorded as a render.
func isImageLoad(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if r.Header.Get("Sec-Fetch-Dest") != "" || r.Header.Get("Sec-Fetch-Mode") != "" ||
		r.Header.Get("Sec-Fetch-Site") != "" || r.Header.Get("Sec-Fetch-User") != "" {
		return r.Header.Get("Sec-Fetch-Dest") == "image"
	}
	return strings.Contains(r.Header.Get("Accept"), "image/")
}

// serveFallbackPixel records a well-signed nonce as rendered on this machine
// and returns the image. Anything else is a 404 and records nothing.
func (h *ChallengeHandler) serveFallbackPixel(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Cache-Control", "no-store")
	now := time.Now()
	nonce, exp, ok := verifyFallbackPixel(h.app.Secret(), h.app.PassPolicy(), clientIP(r), r.UserAgent(), r.URL.Query().Get(fallbackPixelParam), now)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return nil
	}
	if isImageLoad(r) {
		h.app.FallbackState().Rendered.Add(nonce, exp, now)
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Content-Length", strconv.Itoa(len(transparentGIF)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(transparentGIF)
	}
	return nil
}

// fallbackFailure names the first pass condition a fallback POST misses, or
// "" when it passes. The nonce is claimed (spent) atomically before the
// budget is charged, so concurrent replays of one nonce lose the claim and
// use no budget. A claimed nonce that then hits the budget stays spent; the
// visitor gets a fresh challenge anyway.
func (h *ChallengeHandler) fallbackFailure(r *http.Request, p fallbackPayload, now time.Time) string {
	fb, st := h.app.Fallback(), h.app.FallbackState()
	exp := time.Unix(p.Exp, 0)
	switch {
	case !fallbackCookieMatches(r, h.app.Secret(), p.Nonce):
		return "cookie"
	case !st.Rendered.Has(p.Nonce, now):
		return "not_rendered"
	case now.Sub(time.UnixMilli(p.Iat)) < fb.MinDwell:
		return "too_fast"
	case !st.Spent.AddIfAbsent(p.Nonce, exp, now):
		return "replayed"
	case !st.Limiter.Allow(p.Prefix, fb.MaxPerHour, now):
		return "rate_limited"
	}
	return ""
}

// handleFallbackVerify checks a fallback form POST. A pass gets a
// non-rolling pass cookie with the fallback TTL; a failure takes the same
// path as a failed solve.
func (h *ChallengeHandler) handleFallbackVerify(w http.ResponseWriter, r *http.Request, ip string) error {
	pol, now := h.app.PassPolicy(), time.Now()
	p, err := verifyFallbackToken(h.app.Secret(), pol, r.FormValue("fallback"), ip, r.UserAgent(), now)
	if err != nil || h.fallbackFailure(r, p, now) != "" {
		ret := safeReturn(r.FormValue("ret"))
		if err == nil {
			ret = safeReturn(p.Ret)
		}
		return h.verifyFailed(w, r, ret)
	}
	fpol := pol
	fpol.IdleTTL, fpol.MaxTTL = h.app.Fallback().PassTTL, h.app.Fallback().PassTTL
	exp := fpol.InitialExp(now, now)
	setPassCookie(w, IssuePassCookie(h.app.Secret(), fpol, ip, r.UserAgent(), time.Time{}, exp), exp, now)
	setFallbackCookie(w, h.app.Secret(), withoutNonce(readFallbackNonces(r, h.app.Secret()), p.Nonce))
	setOutcome(r, "passed_fallback")
	return h.verifyPassed(w, r, safeReturn(p.Ret))
}

// fallbackView is what the challenge page needs to render the fallback.
type fallbackView struct {
	Token      string
	PixelURL   string
	VerifyPath string
	Ret        string
}

const fallbackCSS = `
.apx-fallback { margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--line); }
.apx-fallback-proof { display: block; width: 1px; height: 1px; margin: 0 auto; background: url("{{PIXEL}}") no-repeat; }
`

const fallbackFormHTML = `<form class="apx-fallback-form" method="POST" action="{{VERIFY_PATH}}">
<input type="hidden" name="mode" value="fallback">
<input type="hidden" name="fallback" value="{{TOKEN}}">
<input type="hidden" name="ret" value="{{RET}}">
<span class="apx-fallback-proof" aria-hidden="true"></span>
<p><button type="submit" class="{{BUTTON_CLASS}}">Continue</button></p>
</form>`

const fallbackNoscriptHTML = `<p class="muted">This site checks browsers with JavaScript, which isn't running here. You can continue without it.</p>
{{FORM}}
<p class="muted">Or turn JavaScript on for this site, then try again.</p>
<p><a class="button button-secondary" href="{{RET}}">Try again</a></p>`

const fallbackSlotHTML = `<div class="apx-fallback">
<p class="muted">If Retry doesn't work, you can continue without the automatic check.</p>
{{FORM}}
</div>`

// noscriptDefaultBody is the original <noscript> copy, kept when the
// fallback is off so the page is byte-identical.
const noscriptDefaultBody = `<p class="muted">This site needs JavaScript to check your browser. Turn JavaScript on for this site, then try again.</p>
<p><a class="button" href="{{RET}}">Try again</a></p>`

// renderFallback returns the extra CSS, the <noscript> body and the failure
// panel slot for fb. Everything interpolated is escaped for its context.
func renderFallback(fb fallbackView) (css, noscript, slot string) {
	ret := html.EscapeString(safeReturn(fb.Ret))
	form := func(buttonClass string) string {
		return strings.NewReplacer(
			"{{VERIFY_PATH}}", html.EscapeString(fb.VerifyPath),
			"{{TOKEN}}", html.EscapeString(fb.Token),
			"{{RET}}", ret,
			"{{BUTTON_CLASS}}", buttonClass,
		).Replace(fallbackFormHTML)
	}
	css = strings.Replace(fallbackCSS, "{{PIXEL}}", cssStringEscape(fb.PixelURL), 1)
	noscript = strings.NewReplacer("{{FORM}}", form("button"), "{{RET}}", ret).Replace(fallbackNoscriptHTML)
	slot = strings.Replace(fallbackSlotHTML, "{{FORM}}", form("button button-secondary"), 1)
	return css, noscript, slot
}

// cssStringEscape escapes s for a double-quoted CSS string inside a <style>
// element: anything outside a conservative URL alphabet becomes a CSS hex
// escape, so no quote, backslash, newline or "</style" survives.
func cssStringEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("/_.-?=&%~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteString(`\`)
		b.WriteString(strconv.FormatInt(int64(c), 16))
		b.WriteByte(' ')
	}
	return b.String()
}

// FallbackLimiter counts fallback passes per client prefix in a sliding hour,
// bounded to max prefixes (least recently used evicted).
type FallbackLimiter struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[string]*list.Element
}

type limiterEntry struct {
	key   string
	times []int64 // unix nanoseconds of recent passes, oldest first
}

func NewFallbackLimiter(max int) *FallbackLimiter {
	if max <= 0 {
		max = 1
	}
	return &FallbackLimiter{max: max, ll: list.New(), m: make(map[string]*list.Element)}
}

// Allow records a pass for key and reports true when fewer than n passes were
// recorded for it in the last hour; otherwise it records nothing and reports
// false.
func (l *FallbackLimiter) Allow(key string, n int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-fallbackRateWindow).UnixNano()
	el, ok := l.m[key]
	if !ok {
		el = l.ll.PushFront(&limiterEntry{key: key})
		l.m[key] = el
		for l.ll.Len() > l.max {
			back := l.ll.Back()
			l.ll.Remove(back)
			delete(l.m, back.Value.(*limiterEntry).key)
		}
	} else {
		l.ll.MoveToFront(el)
	}
	e := el.Value.(*limiterEntry)
	kept := e.times[:0]
	for _, t := range e.times {
		if t > cutoff {
			kept = append(kept, t)
		}
	}
	e.times = kept
	if len(e.times) >= n {
		return false
	}
	e.times = append(e.times, now.UnixNano())
	return true
}

// ExpiringSet is a bounded, concurrency-safe set of keys that each expire.
// Expired keys count as absent and are dropped on the next add. Past max
// entries, the record that expires soonest is evicted, so an expired record
// always goes before a live one.
type ExpiringSet struct {
	mu  sync.Mutex
	max int
	h   expiringHeap // min-heap by exp
	m   map[string]*expiringEntry
}

type expiringEntry struct {
	key   string
	exp   int64 // unix seconds; the key is live while now <= exp
	index int   // position in the heap
}

type expiringHeap []*expiringEntry

func (h expiringHeap) Len() int           { return len(h) }
func (h expiringHeap) Less(i, j int) bool { return h[i].exp < h[j].exp }
func (h expiringHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *expiringHeap) Push(x any) {
	e := x.(*expiringEntry)
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *expiringHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return e
}

func NewExpiringSet(max int) *ExpiringSet {
	if max <= 0 {
		max = 1
	}
	return &ExpiringSet{max: max, m: make(map[string]*expiringEntry)}
}

// Len is the number of records held, live or not yet dropped.
func (s *ExpiringSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.h)
}

// Add records key until exp, replacing any earlier record.
func (s *ExpiringSet) Add(key string, exp, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.add(key, exp, now)
}

// AddIfAbsent records key until exp and reports true, unless a live record
// already exists (then it reports false and changes nothing).
func (s *ExpiringSet) AddIfAbsent(key string, exp, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live(key, now) {
		return false
	}
	s.add(key, exp, now)
	return true
}

// Has reports whether key has a live record.
func (s *ExpiringSet) Has(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.live(key, now)
}

func (s *ExpiringSet) live(key string, now time.Time) bool {
	e, ok := s.m[key]
	return ok && now.Unix() <= e.exp
}

func (s *ExpiringSet) add(key string, exp, now time.Time) {
	if e, ok := s.m[key]; ok {
		e.exp = exp.Unix()
		heap.Fix(&s.h, e.index)
	} else {
		e := &expiringEntry{key: key, exp: exp.Unix()}
		heap.Push(&s.h, e)
		s.m[key] = e
	}
	// Drop expired records, then evict the soonest-expiring down to max.
	for len(s.h) > 0 && s.h[0].exp < now.Unix() {
		delete(s.m, heap.Pop(&s.h).(*expiringEntry).key)
	}
	for len(s.h) > s.max {
		delete(s.m, heap.Pop(&s.h).(*expiringEntry).key)
	}
}

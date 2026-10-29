package apxchallenge

import (
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&ChallengeApp{})
}

const (
	defaultDifficulty = 16
	defaultVerifyPath = "/__apx_challenge/verify"
)

// AppRef is what the handler depends on; tests inject a fake.
type AppRef interface {
	Secret() string
	Difficulty() int
	VerifyPath() string
	VerifyDifficulty() int
	VerifyTokenTTL() time.Duration
	VerifyScoring() string
	VerifyBodyCap() int64
	// PassPolicy is the pass-cookie lifetime / binding policy (pass_* keys).
	PassPolicy() PassPolicy
	// ReplayLRU is the process-wide, app-owned set of recently-seen verify-token
	// nonces. Shared across all verify routes so a token is single-use per machine.
	ReplayLRU() *NonceLRU
	// Fallback is the render-check fallback config (fallback_* keys).
	Fallback() FallbackConfig
	// FallbackState is the process-wide rendered-nonce set and pass budget.
	FallbackState() *FallbackState
}

// ChallengeApp is the top-level Caddy app holding the per-cluster challenge
// secret (read inline from config), the PoW difficulty, and the verify endpoint
// path. Config keys mirror what Phoenix emits in apps.apx_challenge.
type ChallengeApp struct {
	// DifficultyCfg / SecretCfg / VerifyPathCfg carry the JSON config keys
	// difficulty / secret / verify_path. They use the *Cfg suffix because Go
	// forbids a struct field and a method sharing a name, and
	// Secret()/Difficulty()/VerifyPath() are the AppRef accessors handlers
	// depend on.
	DifficultyCfg int    `json:"difficulty,omitempty"`
	SecretCfg     string `json:"secret,omitempty"`
	VerifyPathCfg string `json:"verify_path,omitempty"`

	// VerifyDifficultyCfg / VerifyTokenTTLSecondsCfg / VerifyScoringCfg /
	// VerifyBodyCapBytesCfg carry the Edge Verify config keys verify_difficulty /
	// verify_token_ttl_seconds / verify_scoring / verify_body_cap_bytes. Same
	// *Cfg-suffix convention as above.
	VerifyDifficultyCfg      int    `json:"verify_difficulty,omitempty"`
	VerifyTokenTTLSecondsCfg int    `json:"verify_token_ttl_seconds,omitempty"`
	VerifyScoringCfg         string `json:"verify_scoring,omitempty"`
	VerifyBodyCapBytesCfg    int64  `json:"verify_body_cap_bytes,omitempty"`

	// DEPRECATED, ignored. The too_fast/fill_ms scoring it fed was removed (it
	// blocked every real invisible-widget mint — fill_ms is just PoW-solve time).
	// The field is retained ONLY so this binary still accepts a stored config
	// blob that predates the removal: Caddy strict-unmarshals (DisallowUnknownFields)
	// at machine boot, so an unknown key would crash-loop the machine, not just
	// reject a /load. Phoenix no longer emits the key, but a deploy does NOT
	// regenerate stored config blobs — drop this field only after verifying no
	// cluster's stored config blob still contains verify_min_fill_ms (grep the
	// stored blobs; force-regen any lingering cluster first), not after some
	// number of releases.
	VerifyMinFillMsCfg int64 `json:"verify_min_fill_ms,omitempty"`

	// Pass-cookie policy (all optional; zero/absent = the original behaviour:
	// 10-minute non-rolling cookie bound to the client /24 or /64).
	// pass_idle_ttl_seconds: cookie lifetime from issue or last renewal.
	// pass_max_ttl_seconds: absolute cap from the original solve; rolling
	// renewal is on only when it exceeds the idle TTL.
	// pass_ipv4_prefix / pass_ipv6_prefix: client-network width the cookie binds to.
	// pass_bind_user_agent: also bind the cookie to a hash of the User-Agent.
	PassIdleTTLSecondsCfg int  `json:"pass_idle_ttl_seconds,omitempty"`
	PassMaxTTLSecondsCfg  int  `json:"pass_max_ttl_seconds,omitempty"`
	PassIPv4PrefixCfg     int  `json:"pass_ipv4_prefix,omitempty"`
	PassIPv6PrefixCfg     int  `json:"pass_ipv6_prefix,omitempty"`
	PassBindUserAgentCfg  bool `json:"pass_bind_user_agent,omitempty"`

	// Render-check fallback (all optional; absent = off, page unchanged).
	// fallback_enabled: offer the no-JavaScript fallback form.
	// fallback_pass_ttl_seconds: non-rolling pass-cookie lifetime it earns.
	// fallback_max_per_hour: fallback passes per client prefix per hour, per machine.
	// fallback_min_dwell_seconds: minimum time from page issue to the POST.
	FallbackEnabledCfg         bool `json:"fallback_enabled,omitempty"`
	FallbackPassTTLSecondsCfg  int  `json:"fallback_pass_ttl_seconds,omitempty"`
	FallbackMaxPerHourCfg      int  `json:"fallback_max_per_hour,omitempty"`
	FallbackMinDwellSecondsCfg int  `json:"fallback_min_dwell_seconds,omitempty"`

	logger     *zap.Logger
	secret     string
	difficulty int
	verifyPath string

	verifyDifficulty int
	verifyTokenTTL   time.Duration
	verifyScoring    string
	verifyBodyCap    int64
	replayLRU        *NonceLRU
	passPolicy       PassPolicy
	fallback         FallbackConfig
}

// defaultReplayLRUSize bounds the per-machine seen-nonce set. Best-effort
// single-use — cluster-wide uniqueness is not attempted.
const defaultReplayLRUSize = 65536

// processReplayLRU is the seen-nonce set every ChallengeApp shares. It lives
// at package level so a config reload (which re-provisions the app) does not
// forget which tokens and solved challenges were already used. Nonces are
// random and only recorded after HMAC verification, so one set is safe across
// secrets.
var processReplayLRU = NewNonceLRU(defaultReplayLRUSize)

func (*ChallengeApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "apx_challenge",
		New: func() caddy.Module { return new(ChallengeApp) },
	}
}

func (a *ChallengeApp) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()

	a.difficulty = a.DifficultyCfg
	if a.difficulty <= 0 {
		a.difficulty = defaultDifficulty
	}
	a.verifyPath = a.VerifyPathCfg
	if a.verifyPath == "" {
		a.verifyPath = defaultVerifyPath
	}
	a.secret = a.SecretCfg
	if a.secret == "" {
		return fmt.Errorf("apx_challenge app: secret is required (config key \"secret\")")
	}

	if a.verifyDifficulty = a.VerifyDifficultyCfg; a.verifyDifficulty <= 0 {
		a.verifyDifficulty = 14
	}
	if s := a.VerifyTokenTTLSecondsCfg; s > 0 {
		a.verifyTokenTTL = time.Duration(s) * time.Second
	} else {
		a.verifyTokenTTL = 600 * time.Second
	}
	switch a.VerifyScoringCfg {
	case "off", "lenient", "strict":
		a.verifyScoring = a.VerifyScoringCfg
	default:
		a.verifyScoring = "lenient"
	}
	if a.verifyBodyCap = a.VerifyBodyCapBytesCfg; a.verifyBodyCap <= 0 {
		a.verifyBodyCap = 1 << 20
	}
	a.replayLRU = processReplayLRU

	pol, err := buildPassPolicy(a.PassIdleTTLSecondsCfg, a.PassMaxTTLSecondsCfg,
		a.PassIPv4PrefixCfg, a.PassIPv6PrefixCfg, a.PassBindUserAgentCfg)
	if err != nil {
		return err
	}
	a.passPolicy = pol

	fb, err := buildFallbackConfig(a.FallbackEnabledCfg, a.FallbackPassTTLSecondsCfg,
		a.FallbackMaxPerHourCfg, a.FallbackMinDwellSecondsCfg)
	if err != nil {
		return err
	}
	a.fallback = fb

	return nil
}

// Pass-policy bounds. Ranges keep a misconfiguration from silently producing a
// cookie that is either useless or far more portable than intended.
const (
	minPassIdleTTLSeconds = 60
	maxPassIdleTTLSeconds = 86400  // 1 day
	maxPassMaxTTLSeconds  = 604800 // 7 days
	minPassIPv4Prefix     = 16
	maxPassIPv4Prefix     = 32
	minPassIPv6Prefix     = 32
	maxPassIPv6Prefix     = 128
)

func buildPassPolicy(idleS, maxS, v4, v6 int, bindUA bool) (PassPolicy, error) {
	pol := DefaultPassPolicy()
	switch {
	case idleS < 0:
		return pol, fmt.Errorf("apx_challenge app: pass_idle_ttl_seconds must not be negative (got %d)", idleS)
	case idleS > 0 && (idleS < minPassIdleTTLSeconds || idleS > maxPassIdleTTLSeconds):
		return pol, fmt.Errorf("apx_challenge app: pass_idle_ttl_seconds must be %d-%d (got %d)", minPassIdleTTLSeconds, maxPassIdleTTLSeconds, idleS)
	case idleS > 0:
		pol.IdleTTL = time.Duration(idleS) * time.Second
	}
	pol.MaxTTL = pol.IdleTTL
	switch {
	case maxS < 0:
		return pol, fmt.Errorf("apx_challenge app: pass_max_ttl_seconds must not be negative (got %d)", maxS)
	case maxS > maxPassMaxTTLSeconds:
		return pol, fmt.Errorf("apx_challenge app: pass_max_ttl_seconds must be at most %d (got %d)", maxPassMaxTTLSeconds, maxS)
	case maxS > 0 && time.Duration(maxS)*time.Second < pol.IdleTTL:
		return pol, fmt.Errorf("apx_challenge app: pass_max_ttl_seconds (%d) must be 0 or at least pass_idle_ttl_seconds (%d)", maxS, int(pol.IdleTTL.Seconds()))
	case maxS > 0:
		pol.MaxTTL = time.Duration(maxS) * time.Second
	}
	if v4 != 0 {
		if v4 < minPassIPv4Prefix || v4 > maxPassIPv4Prefix {
			return pol, fmt.Errorf("apx_challenge app: pass_ipv4_prefix must be %d-%d (got %d)", minPassIPv4Prefix, maxPassIPv4Prefix, v4)
		}
		pol.IPv4Prefix = v4
	}
	if v6 != 0 {
		if v6 < minPassIPv6Prefix || v6 > maxPassIPv6Prefix {
			return pol, fmt.Errorf("apx_challenge app: pass_ipv6_prefix must be %d-%d (got %d)", minPassIPv6Prefix, maxPassIPv6Prefix, v6)
		}
		pol.IPv6Prefix = v6
	}
	pol.BindUserAgent = bindUA
	return pol, nil
}

func (a *ChallengeApp) Start() error { return nil }
func (a *ChallengeApp) Stop() error  { return nil }

func (a *ChallengeApp) Secret() string     { return a.secret }
func (a *ChallengeApp) Difficulty() int    { return a.difficulty }
func (a *ChallengeApp) VerifyPath() string { return a.verifyPath }

func (a *ChallengeApp) VerifyDifficulty() int         { return a.verifyDifficulty }
func (a *ChallengeApp) VerifyTokenTTL() time.Duration { return a.verifyTokenTTL }
func (a *ChallengeApp) VerifyScoring() string         { return a.verifyScoring }
func (a *ChallengeApp) VerifyBodyCap() int64          { return a.verifyBodyCap }
func (a *ChallengeApp) ReplayLRU() *NonceLRU          { return a.replayLRU }
func (a *ChallengeApp) PassPolicy() PassPolicy        { return a.passPolicy }
func (a *ChallengeApp) Fallback() FallbackConfig      { return a.fallback }
func (a *ChallengeApp) FallbackState() *FallbackState { return processFallbackState }

var (
	_ caddy.App         = (*ChallengeApp)(nil)
	_ caddy.Provisioner = (*ChallengeApp)(nil)
	_ AppRef            = (*ChallengeApp)(nil)
)

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
	// ReplayLRU is the process-wide, app-owned set of recently-seen verify-token
	// nonces. Shared across all verify routes so a token is single-use per machine.
	ReplayLRU() *NonceLRU
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

	logger     *zap.Logger
	secret     string
	difficulty int
	verifyPath string

	verifyDifficulty int
	verifyTokenTTL   time.Duration
	verifyScoring    string
	verifyBodyCap    int64
	replayLRU        *NonceLRU
}

// defaultReplayLRUSize bounds the per-machine seen-nonce set. Best-effort
// single-use — cluster-wide uniqueness is not attempted.
const defaultReplayLRUSize = 65536

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
	a.replayLRU = NewNonceLRU(defaultReplayLRUSize)

	return nil
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

var (
	_ caddy.App         = (*ChallengeApp)(nil)
	_ caddy.Provisioner = (*ChallengeApp)(nil)
	_ AppRef            = (*ChallengeApp)(nil)
)

package apxchallenge

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

// fakeClock is a settable clock for a difficultyHistory.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newClockedHistory() (*difficultyHistory, *fakeClock) {
	c := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	return &difficultyHistory{now: c.now}, c
}

// reload starts an instance at next, then stops the one at prev, as Caddy does.
func reload(d *difficultyHistory, prev, next int) {
	d.start(next)
	d.stop(prev)
}

func (d *difficultyHistory) at(except int) []int {
	return d.inForceSince(d.clock().Add(-staleDifficultyWindow), except)
}

func TestDifficultyHistoryKeepsEveryDifficultyInForceInTheWindow(t *testing.T) {
	d, c := newClockedHistory()
	d.start(16)
	reload(d, 16, 16) // a reload with the same difficulty is no change
	require.Empty(t, d.at(16))

	// 16 -> 18 -> 20 within two minutes: both earlier ones are remembered.
	c.advance(time.Minute)
	reload(d, 16, 18)
	c.advance(time.Minute)
	reload(d, 18, 20)
	c.advance(time.Minute)
	require.ElementsMatch(t, []int{16, 18}, d.at(20))

	// 16 stopped at +1m: forgotten once that is more than the window ago.
	c.advance(staleDifficultyWindow - 2*time.Minute + time.Second)
	require.ElementsMatch(t, []int{18}, d.at(20))

	// Back to 16: the asking instance's own difficulty is never listed, and
	// the running one always is, however long ago it started.
	reload(d, 20, 16)
	require.ElementsMatch(t, []int{18, 20}, d.at(16))
	c.advance(time.Hour)
	require.Empty(t, d.at(16))
	require.Equal(t, []int{16}, d.at(20))
	// A config started and stopped at once (another app failed) is in force
	// for the window after it, and its Stop prunes nothing still running.
	d.start(24)
	d.stop(24)
	require.ElementsMatch(t, []int{24}, d.at(16))
	require.ElementsMatch(t, []int{16, 24}, d.at(20))
}

func TestDifficultyHistoryAlternatingValuesKeepEveryUnexpiredOne(t *testing.T) {
	d, c := newClockedHistory()
	d.start(14)
	reload(d, 14, 16)
	// Far more than 32 changes between two values inside the window.
	prev := 16
	for i := 0; i < 100; i++ {
		next := 34 - prev // 16 <-> 18
		c.advance(time.Second)
		reload(d, prev, next)
		prev = next
	}
	require.ElementsMatch(t, []int{14, 16, 18}, d.at(0))
	// Bounded by distinct values, not by changes.
	require.Len(t, d.lastInForce, 3)

	// Expired entries are dropped, not just hidden, at the next Stop.
	c.advance(staleDifficultyWindow + time.Second)
	reload(d, prev, 34-prev)
	require.Len(t, d.lastInForce, 2)
}

func TestInFlightHandlerSeesTheDifficultyOfTheConfigReplacingIt(t *testing.T) {
	d, c := newClockedHistory()
	app := func(diff int) *ChallengeApp {
		a := &ChallengeApp{SecretCfg: "h-secret", DifficultyCfg: diff, difficulties: d}
		require.NoError(t, a.Provision(caddy.Context{}))
		require.NoError(t, a.Start())
		return a
	}
	old := app(12)
	next := app(8) // the reload started; old is not stopped yet

	// A request still running on the old instance verifies a page issued by
	// the new one: the proof meets 8, not 12.
	tok := IssueChallenge("h-secret", "203.0.113.5", "/", time.Now().Add(challengeTokenTTL))
	form := url.Values{"challenge": {tok}, "solution": {solutionBetween(tok, 8, 12)}}
	r := verifyReq(form, "203.0.113.5", "UA")
	require.Equal(t, http.StatusForbidden, serveReq(t, &ChallengeHandler{app: old}, r).Code)
	_, reason := outcomeAndReason(r)
	require.Equal(t, reasonStaleDifficulty, reason)

	// Once old stops, a request on it still sees 8 (running) and its own 12 is
	// still recent for the new instance.
	require.NoError(t, old.Stop())
	require.Equal(t, []int{8}, old.PreviousDifficulties(c.now()))
	require.Equal(t, []int{12}, next.PreviousDifficulties(c.now()))
	c.advance(staleDifficultyWindow + time.Second)
	require.Empty(t, next.PreviousDifficulties(c.now()))
}

// failingApp fails its Start, after noting whether apx_challenge started first.
type failingApp struct{}

var challengeStartedFirst bool

func (failingApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "apx_challenge_test_failing", New: func() caddy.Module { return new(failingApp) }}
}
func (failingApp) Start() error {
	processDifficulties.mu.Lock()
	challengeStartedFirst = processDifficulties.running[20] > 0
	processDifficulties.mu.Unlock()
	return errors.New("test app refuses to start")
}
func (failingApp) Stop() error { return nil }

func init() { caddy.RegisterModule(failingApp{}) }

func loadConfig(t *testing.T, difficulty int, failing bool) error {
	t.Helper()
	apps := map[string]any{"apx_challenge": map[string]any{"secret": "s", "difficulty": difficulty}}
	if failing {
		apps["apx_challenge_test_failing"] = map[string]any{}
	}
	cfg, err := json.Marshal(map[string]any{
		"admin": map[string]any{"disabled": true, "config": map[string]any{"persist": false}},
		"apps":  apps,
	})
	require.NoError(t, err)
	return caddy.Load(cfg, true)
}

func TestConfigRolledBackAtStartKeepsTheRunningDifficultyInForce(t *testing.T) {
	d, c := newClockedHistory()
	saved := processDifficulties
	processDifficulties = d
	t.Cleanup(func() {
		_ = caddy.Stop()
		processDifficulties = saved
	})

	require.NoError(t, loadConfig(t, 16, false))
	// Caddy starts apps in map order: retry until apx_challenge started before
	// the failing app, so it was started and then stopped by the rollback.
	for i := 0; !challengeStartedFirst; i++ {
		require.Less(t, i, 200, "apx_challenge never started first")
		require.Error(t, loadConfig(t, 20, true))
	}

	// 16 kept serving. Nine minutes later the config really moves to 20.
	c.advance(9 * time.Minute)
	require.NoError(t, loadConfig(t, 20, false))
	c.advance(2 * time.Minute)

	cur, err := caddy.ActiveContext().App("apx_challenge")
	require.NoError(t, err)
	require.Equal(t, 20, cur.(*ChallengeApp).Difficulty())
	// 16 was in force until two minutes ago, not eleven.
	require.Contains(t, cur.(*ChallengeApp).PreviousDifficulties(c.now()), 16)
}

func TestDifficultyIsNotRecordedWhenTheConfigIsRejectedAtProvision(t *testing.T) {
	d, _ := newClockedHistory()
	start := func(cfg *ChallengeApp) error {
		cfg.difficulties = d
		if err := cfg.Provision(caddy.Context{}); err != nil {
			return err
		}
		return cfg.Start()
	}
	require.NoError(t, start(&ChallengeApp{SecretCfg: "s", DifficultyCfg: 16}))
	require.NoError(t, start(&ChallengeApp{SecretCfg: "s", DifficultyCfg: 20}))

	// A config rejected at Provision never reaches Start, and changes nothing.
	require.Error(t, start(&ChallengeApp{SecretCfg: "s", DifficultyCfg: 18, PassIdleTTLSecondsCfg: 1}))
	// Provisioned but never started: nothing either.
	unstarted := &ChallengeApp{SecretCfg: "s", DifficultyCfg: 22, difficulties: d}
	require.NoError(t, unstarted.Provision(caddy.Context{}))

	live := &ChallengeApp{SecretCfg: "s", DifficultyCfg: 20, difficulties: d}
	require.NoError(t, live.Provision(caddy.Context{}))
	require.Equal(t, []int{16}, live.PreviousDifficulties(time.Now()))
}

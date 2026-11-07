package apxchallenge

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

const histSecret, histIP, histUA = "h-secret", "203.0.113.5", "UA"

func handlerAt(diff int, d *difficultyHistory) *ChallengeHandler {
	return &ChallengeHandler{app: fakeApp{sec: histSecret, diff: diff, vp: defaultVerifyPath}, difficulties: d}
}

// issuePage serves one challenge page through h.
func issuePage(t *testing.T, h *ChallengeHandler) {
	t.Helper()
	require.Equal(t, http.StatusOK, serveReq(t, h, browserReq("/")).Code)
}

// verifyReason posts a solution with at least lo and fewer than hi leading
// zero bits, and returns the failure reason h records.
func verifyReason(t *testing.T, h *ChallengeHandler, lo, hi int) any {
	t.Helper()
	tok := IssueChallenge(histSecret, histIP, "/", time.Now().Add(challengeTokenTTL))
	r := verifyReq(url.Values{"challenge": {tok}, "solution": {solutionBetween(tok, lo, hi)}}, histIP, histUA)
	require.Equal(t, http.StatusForbidden, serveReq(t, h, r).Code)
	_, reason := outcomeAndReason(r)
	return reason
}

func TestStaleDifficultyFollowsIssuedPages(t *testing.T) {
	d := &difficultyHistory{}
	// Raised 8 -> 10 -> 12 within the window: both earlier ones issued pages.
	issuePage(t, handlerAt(8, d))
	issuePage(t, handlerAt(10, d))
	raised := handlerAt(12, d)
	require.Equal(t, reasonStaleDifficulty, verifyReason(t, raised, 8, 12))
	// A proof meeting exactly an issued difficulty counts.
	require.Equal(t, reasonStaleDifficulty, verifyReason(t, raised, 10, 11))
	// A proof meeting no issued difficulty is a wrong proof right after a change.
	require.Equal(t, reasonProof, verifyReason(t, raised, 0, 8))

	// No page at another difficulty: the same short proof is a wrong proof.
	steady := handlerAt(12, &difficultyHistory{})
	issuePage(t, steady)
	require.Equal(t, reasonProof, verifyReason(t, steady, 8, 12))
}

func TestDifficultyThatNeverIssuedAPageIsNotAccepted(t *testing.T) {
	d := &difficultyHistory{}
	issuePage(t, handlerAt(10, d))
	// The proof meets 8 and 9, which never issued a page here, but not 10.
	require.Equal(t, reasonProof, verifyReason(t, handlerAt(12, d), 8, 10))

	// A page issued just over the window ago no longer counts; just inside does.
	old := &difficultyHistory{}
	old.issued(8, time.Now().Add(-10*time.Minute-time.Second))
	require.Equal(t, reasonProof, verifyReason(t, handlerAt(12, old), 8, 12))
	old.issued(8, time.Now().Add(-10*time.Minute+5*time.Second))
	require.Equal(t, reasonStaleDifficulty, verifyReason(t, handlerAt(12, old), 8, 12))

	// Out-of-range difficulties are never recorded, and never panic.
	d.issued(-1, time.Now())
	d.issued(0, time.Now())
	d.issued(maxTrackedDifficulty+1, time.Now())
	require.False(t, d.issuedSince(0, time.Time{}))
	require.False(t, d.issuedSince(maxTrackedDifficulty+1, time.Time{}))
}

func TestAlternatingDifficultiesKeepEveryRecentOne(t *testing.T) {
	d := &difficultyHistory{}
	t0 := time.Now()
	d.issued(14, t0)
	for i := 0; i < 100; i++ { // far more changes than any list would keep
		d.issued(16+2*(i%2), t0.Add(time.Duration(i)*time.Second))
	}
	at := t0.Add(2 * time.Minute)
	for _, diff := range []int{14, 16, 18} {
		require.True(t, d.issuedSince(diff, at.Add(-staleDifficultyWindow)), diff)
	}
	require.False(t, d.issuedSince(15, at.Add(-staleDifficultyWindow)))
	require.False(t, d.issuedSince(14, t0.Add(staleDifficultyWindow+time.Second).Add(-staleDifficultyWindow)))
}

func startedApp(t *testing.T, diff int) *ChallengeApp {
	t.Helper()
	a := &ChallengeApp{SecretCfg: histSecret, DifficultyCfg: diff}
	require.NoError(t, a.Provision(caddy.Context{}))
	require.NoError(t, a.Start())
	return a
}

func TestInFlightRequestOnTheOldInstanceSeesTheNewDifficulty(t *testing.T) {
	d := &difficultyHistory{}
	old := &ChallengeHandler{app: startedApp(t, 12), difficulties: d}
	// The reload started an instance at 8, which issues a page before old stops.
	issuePage(t, &ChallengeHandler{app: startedApp(t, 8), difficulties: d})
	require.Equal(t, reasonStaleDifficulty, verifyReason(t, old, 8, 12))
}

func TestPageFromAnInstanceThatNeverStartedCounts(t *testing.T) {
	// Caddy can start the HTTP app, then fail another app, before
	// apx_challenge starts: pages served meanwhile still count.
	d := &difficultyHistory{}
	a := &ChallengeApp{SecretCfg: histSecret, DifficultyCfg: 10}
	require.NoError(t, a.Provision(caddy.Context{}))
	issuePage(t, &ChallengeHandler{app: a, difficulties: d})
	require.Equal(t, reasonStaleDifficulty, verifyReason(t, handlerAt(12, d), 10, 12))
}

func TestDuplicateStopDoesNotHideARunningDifficulty(t *testing.T) {
	d := &difficultyHistory{}
	a, b := startedApp(t, 10), startedApp(t, 10)
	require.NoError(t, a.Stop())
	require.NoError(t, a.Stop())
	issuePage(t, &ChallengeHandler{app: b, difficulties: d})
	require.Equal(t, reasonStaleDifficulty, verifyReason(t, handlerAt(12, d), 10, 12))
}

// failingApp refuses to start.
type failingApp struct{}

func (failingApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "apx_challenge_test_failing", New: func() caddy.Module { return new(failingApp) }}
}
func (failingApp) Start() error { return errors.New("test app refuses to start") }
func (failingApp) Stop() error  { return nil }

func init() { caddy.RegisterModule(failingApp{}) }

func loadConfig(t *testing.T, difficulty int, admin map[string]any, extraApps ...string) error {
	t.Helper()
	apps := map[string]any{"apx_challenge": map[string]any{"secret": histSecret, "difficulty": difficulty}}
	for _, name := range extraApps {
		apps[name] = map[string]any{}
	}
	cfg, err := json.Marshal(map[string]any{"admin": admin, "apps": apps})
	require.NoError(t, err)
	return caddy.Load(cfg, true)
}

func noAdmin() map[string]any {
	return map[string]any{"disabled": true, "config": map[string]any{"persist": false}}
}

func TestRejectedConfigsRecordNoDifficulty(t *testing.T) {
	saved := processDifficulties
	processDifficulties = &difficultyHistory{}
	t.Cleanup(func() {
		_ = caddy.Stop()
		processDifficulties = saved
	})

	require.NoError(t, loadConfig(t, 16, noAdmin()))
	// Another app fails at start: Caddy may start and stop apx_challenge first.
	for i := 0; i < 20; i++ {
		require.Error(t, loadConfig(t, 10, noAdmin(), "apx_challenge_test_failing"))
	}
	// Every app started, then finishSettingUp fails: Caddy cleans up without Stop.
	admin := noAdmin()
	admin["config"].(map[string]any)["load"] = map[string]any{"module": "apx_challenge_test_no_such_loader"}
	err := loadConfig(t, 11, admin)
	require.ErrorContains(t, err, "loading config loader module")

	for diff := 1; diff <= maxTrackedDifficulty; diff++ {
		require.False(t, processDifficulties.issuedSince(diff, time.Time{}), diff)
	}
	// The running config keeps issuing pages, so after a real move to 20 its
	// 16 counts and the rejected 10 and 11 do not.
	running := &ChallengeHandler{app: fakeApp{sec: histSecret, diff: 16, vp: defaultVerifyPath}}
	issuePage(t, running)
	next := &ChallengeHandler{app: fakeApp{sec: histSecret, diff: 20, vp: defaultVerifyPath}}
	require.Equal(t, reasonStaleDifficulty, verifyReason(t, next, 16, 20))
	require.Equal(t, reasonProof, verifyReason(t, next, 10, 16))
}

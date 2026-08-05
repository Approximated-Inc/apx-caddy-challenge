package apxchallenge

import (
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/stretchr/testify/require"
)

func TestAppProvisionReadsSecretFromConfig(t *testing.T) {
	app := &ChallengeApp{DifficultyCfg: 16, SecretCfg: "test-secret-123", VerifyPathCfg: "/__apx_challenge/verify"}
	require.NoError(t, app.Provision(caddy.Context{}))
	require.Equal(t, "test-secret-123", app.Secret())
	require.Equal(t, 16, app.Difficulty())
	require.Equal(t, "/__apx_challenge/verify", app.VerifyPath())
}

func TestAppProvisionDefaults(t *testing.T) {
	app := &ChallengeApp{SecretCfg: "s"}
	require.NoError(t, app.Provision(caddy.Context{}))
	require.Equal(t, 16, app.Difficulty())
	require.Equal(t, "/__apx_challenge/verify", app.VerifyPath())
	require.Equal(t, "s", app.Secret())
}

func TestAppProvisionErrorsWhenSecretEmpty(t *testing.T) {
	app := &ChallengeApp{}
	require.Error(t, app.Provision(caddy.Context{}))
}

func TestAppModuleID(t *testing.T) {
	require.Equal(t, "apx_challenge", string((&ChallengeApp{}).CaddyModule().ID))
}

func TestVerifyDefaultsApplied(t *testing.T) {
	a := &ChallengeApp{SecretCfg: "s"}
	if err := a.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if a.VerifyDifficulty() != 14 || a.VerifyScoring() != "lenient" || a.VerifyBodyCap() != 1048576 {
		t.Fatalf("defaults wrong: diff=%d scoring=%q cap=%d", a.VerifyDifficulty(), a.VerifyScoring(), a.VerifyBodyCap())
	}
	if a.VerifyTokenTTL() != 600*time.Second {
		t.Fatalf("ttl wrong: ttl=%v", a.VerifyTokenTTL())
	}
}

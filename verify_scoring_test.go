package apxchallenge

import "testing"

func human() Probes { return Probes{FillMs: 5000, Interactions: 8, Webdriver: false} }

func TestScoreOffAlwaysPasses(t *testing.T) {
	worst := Probes{Webdriver: true, MissingAPIs: []string{"a", "b", "c"}}
	if ok, _ := ScoreProbes(worst, "off"); !ok {
		t.Fatal("off mode must always pass")
	}
}

func TestScoreLenientBlocksWebdriverAndMissingAPIs(t *testing.T) {
	if ok, r := ScoreProbes(Probes{Webdriver: true}, "lenient"); ok || r != "webdriver" {
		t.Fatalf("want block webdriver, got ok=%v r=%q", ok, r)
	}
	if ok, r := ScoreProbes(Probes{MissingAPIs: []string{"a", "b", "c"}}, "lenient"); ok || r != "missing_apis" {
		t.Fatalf("want block missing_apis, got ok=%v r=%q", ok, r)
	}
	if ok, _ := ScoreProbes(human(), "lenient"); !ok {
		t.Fatal("human should pass lenient")
	}
}

// Regression guard for the too_fast/no_interaction bug: the invisible widget
// mints on page load, so every real mint has a low FillMs (~PoW-solve time) and
// zero Interactions. Neither may block, or every real browser is refused and
// all protected forms break.
func TestScoreDoesNotBlockOnFillOrInteraction(t *testing.T) {
	bootMint := Probes{FillMs: 50, Interactions: 0, Webdriver: false}
	if ok, r := ScoreProbes(bootMint, "lenient"); !ok {
		t.Fatalf("fast boot-mint must pass lenient, got r=%q", r)
	}
	if ok, r := ScoreProbes(bootMint, "strict"); !ok {
		t.Fatalf("fast boot-mint must pass strict, got r=%q", r)
	}
}

// strict tightens the missing-API threshold (2 vs lenient's 3) but must still
// tolerate ONE legitimately-absent API (e.g. WebGL disabled by a privacy
// setting) so it never mass-blocks a real-but-locked-down browser.
func TestScoreStrictThreshold(t *testing.T) {
	if ok, _ := ScoreProbes(human(), "strict"); !ok {
		t.Fatal("healthy probe must pass strict")
	}
	oneMissing := Probes{MissingAPIs: []string{"WebGLRenderingContext"}}
	if ok, r := ScoreProbes(oneMissing, "strict"); !ok {
		t.Fatalf("strict must tolerate a single missing API, got r=%q", r)
	}
	twoMissing := Probes{MissingAPIs: []string{"WebGLRenderingContext", "IntersectionObserver"}}
	if ok, r := ScoreProbes(twoMissing, "strict"); ok || r != "missing_apis" {
		t.Fatalf("strict must block on two missing APIs, got ok=%v r=%q", ok, r)
	}
	if ok, _ := ScoreProbes(twoMissing, "lenient"); !ok {
		t.Fatal("lenient must tolerate two missing APIs")
	}
}

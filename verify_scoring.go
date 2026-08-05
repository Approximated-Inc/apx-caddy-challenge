package apxchallenge

// Probes is the JSON the widget posts to /__apx_verify/token. All fields are
// attacker-controlled — treat as untrusted signal, never as ground truth.
type Probes struct {
	FillMs       int64    `json:"fill_ms"`      // load → token-request elapsed
	Interactions int      `json:"interactions"` // input/pointer events seen
	Webdriver    bool     `json:"webdriver"`    // navigator.webdriver
	MissingAPIs  []string `json:"missing_apis"` // expected browser APIs found absent
}

// ScoreProbes applies the mode's ruleset to the widget's probe payload and
// returns (ok, reason); reason is "" when ok. It errs toward passing: a false
// block silently breaks a real customer form.
//
// Only signals valid AT TOKEN-MINT TIME may block here. The widget is invisible
// and mints the token transparently on page load, so the behavioral probes that
// accrue over a visit — FillMs (load→mint elapsed) and Interactions — are still
// ~zero at mint for EVERY real visitor: FillMs is really just the PoW-solve time
// (tens to a few hundred ms) and no interaction has happened yet. Gating the
// mint on them blocked essentially all real browsers, so they are collected for
// possible future submit-time scoring but never block the mint. The load-valid
// tells are navigator.webdriver and a run of expected-but-absent browser APIs;
// those, plus the proof-of-work the mint already required, gate the token.
func ScoreProbes(p Probes, mode string) (bool, string) {
	if mode == "off" {
		return true, ""
	}
	if p.Webdriver {
		return false, "webdriver"
	}
	// A genuine modern browser exposes all probed APIs (the widget only probes
	// universal ones — see missingAPIs in assets/verify_widget.js); several
	// missing at once is a strong headless/bot tell. strict is the opt-in,
	// more-aggressive mode; lenient is the safe default. strict still tolerates a
	// single absence as conservative margin: a widget-capable browser normally
	// exposes all 8 probed APIs, so requiring 2+ avoids blocking on any single
	// unexpected/anomalous absence.
	missingThreshold := 3
	if mode == "strict" {
		missingThreshold = 2
	}
	if len(p.MissingAPIs) >= missingThreshold {
		return false, "missing_apis"
	}
	return true, ""
}

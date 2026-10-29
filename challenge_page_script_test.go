package apxchallenge

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// pageScriptHarness runs the challenge page's inline failure-UI script in a
// Node vm with a fake DOM, a fake clock and a captured setInterval, then
// replays a list of steps and records snapshots. argv: script path, JSON
// request {html, cookies: "works"|"blocked", cookieEnabled, steps}.
const pageScriptHarness = `
var vm = require("vm"), fs = require("fs");
var src = fs.readFileSync(process.argv[2], "utf8");
var req = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
var out = { snaps: [], reloads: 0, cookieWrites: [], focused: null };
var clock = 1000000, tick = null, cleared = false;
var ids = ["apx-checking", "apx-intro", "apx-verifying", "apx-slow", "apx-failed", "apx-retry", "apx-nocookies", "apx-challenge"];
var els = {};
function mk(id) {
  var el = { id: id, attrs: {}, style: {}, listeners: {}, removed: false };
  el.setAttribute = function (k, v) { el.attrs[k] = String(v); };
  el.removeAttribute = function (k) { delete el.attrs[k]; };
  el.getAttribute = function (k) { return k in el.attrs ? el.attrs[k] : null; };
  el.addEventListener = function (t, f) { (el.listeners[t] = el.listeners[t] || []).push(f); };
  el.focus = function () { out.focused = id; };
  el.getElementsByTagName = function () { return el.button ? [el.button] : []; };
  el.parentNode = { removeChild: function (c) { c.removed = true; } };
  // Initial hidden attribute straight from the rendered markup.
  if (new RegExp('id="' + id + '"[^>]*\\shidden[\\s>]').test(req.html)) el.attrs.hidden = "";
  return el;
}
ids.forEach(function (id) { els[id] = mk(id); });
var slowRetry = mk("slow-retry"), cookieRetry = mk("cookie-retry");
els["apx-failed"].button = els["apx-retry"];
els["apx-nocookies"].button = cookieRetry;
var retries = [slowRetry, els["apx-retry"], cookieRetry];

var jar = {};
var doc = {
  hidden: false, listeners: {},
  getElementById: function (id) { var e = els[id]; return e && !e.removed ? e : null; },
  querySelectorAll: function (q) { return q === "[data-apx-retry]" ? retries : []; },
  addEventListener: function (t, f) { (doc.listeners[t] = doc.listeners[t] || []).push(f); }
};
Object.defineProperty(doc, "cookie", {
  get: function () { return Object.keys(jar).map(function (k) { return k + "=" + jar[k]; }).join("; "); },
  set: function (v) {
    out.cookieWrites.push(v);
    if (req.cookies !== "works") return;
    var parts = v.split(";"), kv = parts[0].split("=");
    var gone = /max-age=0|expires=Thu, 01 Jan 1970/i.test(v);
    if (gone) delete jar[kv[0].trim()]; else jar[kv[0].trim()] = kv.slice(1).join("=");
  }
});
var winListeners = {};
var win = {
  document: doc,
  navigator: { cookieEnabled: req.cookieEnabled !== false },
  location: { reload: function () { out.reloads++; } },
  Date: function () { return { getTime: function () { return clock; } }; },
  setInterval: function (f, ms) { tick = f; return 1; },
  clearInterval: function () { cleared = true; },
  addEventListener: function (t, f) { (winListeners[t] = winListeners[t] || []).push(f); },
  String: String
};
win.window = win;
vm.createContext(win);
vm.runInContext(src, win);

function visible(id) {
  var e = els[id];
  return !e.removed && !("hidden" in e.attrs) && e.style.display !== "none";
}
function snap(label) {
  var s = { label: label, t: clock, form: !els["apx-challenge"].removed };
  ids.forEach(function (id) { s[id] = visible(id); });
  s.reason = els["apx-failed"].getAttribute("data-reason");
  s.cookieReason = els["apx-nocookies"].getAttribute("data-reason");
  s.retryDisabled = retries.map(function (r) { return r.getAttribute("disabled") !== null; });
  s.focused = out.focused;
  out.snaps.push(s);
}
req.steps.forEach(function (st) {
  switch (st.op) {
    case "advance":
      for (var i = 0; i < st.ms; i += 1000) {
        clock += 1000;
        if (st.progress) win.apxChallengeProgress(1);
        if (tick && !cleared) tick();
      }
      break;
    case "progress": win.apxChallengeProgress(1); break;
    case "done": win.apxChallengeDone(); break;
    case "fail": win.apxChallengeFail(st.reason); break;
    case "error": (winListeners.error || []).forEach(function (f) { f({}); }); break;
    case "click": var b = st.id === "apx-retry" ? els["apx-retry"] : (st.id === "slow-retry" ? slowRetry : cookieRetry);
      (b.listeners.click || []).forEach(function (f) { f.call(b); }); break;
    case "snap": snap(st.label); break;
  }
});
out.jar = jar;
process.stdout.write(JSON.stringify(out));
`

var inlineScriptRe = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// pageInlineScript is the failure-UI script from a rendered page (the first
// inline script; the second is the solver).
func pageInlineScript(t *testing.T, html string) string {
	t.Helper()
	m := inlineScriptRe.FindAllStringSubmatch(html, -1)
	require.GreaterOrEqual(t, len(m), 2)
	require.Contains(t, m[0][1], "apxChallengeFail")
	return m[0][1]
}

type pageSnap struct {
	Label         string `json:"label"`
	Form          bool   `json:"form"`
	Checking      bool   `json:"apx-checking"`
	Intro         bool   `json:"apx-intro"`
	Verifying     bool   `json:"apx-verifying"`
	Slow          bool   `json:"apx-slow"`
	Failed        bool   `json:"apx-failed"`
	NoCookies     bool   `json:"apx-nocookies"`
	Reason        string `json:"reason"`
	CookieReason  string `json:"cookieReason"`
	RetryDisabled []bool `json:"retryDisabled"`
	Focused       string `json:"focused"`
}

type pageRun struct {
	Snaps        []pageSnap        `json:"snaps"`
	Reloads      int               `json:"reloads"`
	CookieWrites []string          `json:"cookieWrites"`
	Jar          map[string]string `json:"jar"`
}

func (r pageRun) snap(t *testing.T, label string) pageSnap {
	t.Helper()
	for _, s := range r.Snaps {
		if s.Label == label {
			return s
		}
	}
	t.Fatalf("no snapshot %q", label)
	return pageSnap{}
}

type step map[string]any

func adv(ms int, progress bool) step { return step{"op": "advance", "ms": ms, "progress": progress} }
func snapAt(label string) step       { return step{"op": "snap", "label": label} }

func runPageScript(t *testing.T, cookies string, cookieEnabled bool, steps ...step) pageRun {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH")
	}
	html := renderPage("TOK", 8, "/__apx_challenge/verify", "/x", 0)
	dir := t.TempDir()
	files := map[string]string{
		"harness.js": pageScriptHarness,
		"page.js":    pageInlineScript(t, html),
	}
	reqJSON, err := json.Marshal(map[string]any{"html": html, "cookies": cookies, "cookieEnabled": cookieEnabled, "steps": steps})
	require.NoError(t, err)
	files["req.json"] = string(reqJSON)
	for n, c := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600))
	}
	cmd := exec.Command(node, filepath.Join(dir, "harness.js"), filepath.Join(dir, "page.js"), filepath.Join(dir, "req.json"))
	cmd.Dir = dir
	raw, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		t.Fatalf("node failed: %v\n%s", err, ee.Stderr)
	}
	require.NoError(t, err)
	var run pageRun
	require.NoError(t, json.Unmarshal(raw, &run), string(raw))
	return run
}

func TestPageScriptCookieProbe(t *testing.T) {
	ok := runPageScript(t, "works", true, snapAt("start"))
	s := ok.snap(t, "start")
	require.True(t, s.Form, "probe passed: the solver's form stays")
	require.True(t, s.Checking)
	require.False(t, s.NoCookies)
	require.Empty(t, ok.Jar, "probe cookie deleted again")
	require.Len(t, ok.CookieWrites, 2)
	require.Contains(t, ok.CookieWrites[0], "SameSite=Lax; Secure")
	require.Contains(t, ok.CookieWrites[1], "max-age=0")
	require.Contains(t, ok.CookieWrites[1], "expires=Thu, 01 Jan 1970 00:00:00 GMT")

	for name, run := range map[string]pageRun{
		"blocked":          runPageScript(t, "blocked", true, snapAt("start"), adv(60000, false), snapAt("later")),
		"cookieEnabled=no": runPageScript(t, "works", false, snapAt("start"), adv(60000, false), snapAt("later")),
	} {
		t.Run(name, func(t *testing.T) {
			s := run.snap(t, "start")
			require.False(t, s.Form, "form removed so no PoW is spent")
			require.True(t, s.NoCookies)
			require.False(t, s.Checking)
			require.Equal(t, "cookies", s.CookieReason)
			require.False(t, s.Failed)
			// No timer runs after the cookie panel.
			require.Equal(t, s.NoCookies, run.snap(t, "later").NoCookies)
			require.False(t, run.snap(t, "later").Failed)
		})
	}
}

func TestPageScriptStillCheckingThenStalled(t *testing.T) {
	run := runPageScript(t, "works", true,
		adv(15000, true), snapAt("15s"),
		adv(10000, true), snapAt("25s"),
		adv(30000, true), snapAt("55s"),
		adv(9000, false), snapAt("9s quiet"),
		adv(3000, false), snapAt("12s quiet"),
	)
	s := run.snap(t, "15s")
	require.True(t, s.Checking && s.Intro)
	require.False(t, s.Slow || s.Failed)

	for _, l := range []string{"25s", "55s", "9s quiet"} {
		s = run.snap(t, l)
		require.True(t, s.Checking && s.Slow, l)
		require.False(t, s.Intro || s.Failed, l)
	}
	s = run.snap(t, "12s quiet")
	require.True(t, s.Failed)
	require.False(t, s.Checking)
	require.Equal(t, "stalled", s.Reason)
	require.Equal(t, "apx-retry", s.Focused)
	require.Equal(t, []bool{false, false, false}, s.RetryDisabled)
}

func TestPageScriptNoProgressTimesOut(t *testing.T) {
	run := runPageScript(t, "works", true, adv(19000, false), snapAt("19s"), adv(2000, false), snapAt("21s"))
	require.False(t, run.snap(t, "19s").Failed)
	s := run.snap(t, "21s")
	require.True(t, s.Failed)
	require.Equal(t, "timeout", s.Reason)
}

func TestPageScriptProgressResumesAfterStall(t *testing.T) {
	run := runPageScript(t, "works", true,
		adv(25000, true), adv(12000, false), snapAt("stalled"),
		step{"op": "progress"}, snapAt("resumed"),
		adv(5000, true), snapAt("later"),
		step{"op": "error"}, snapAt("error"),
		step{"op": "progress"}, snapAt("after error"),
	)
	require.True(t, run.snap(t, "stalled").Failed)
	for _, l := range []string{"resumed", "later", "after error"} {
		s := run.snap(t, l)
		require.False(t, s.Failed, l)
		require.True(t, s.Checking && s.Slow, l)
	}
	s := run.snap(t, "error")
	require.True(t, s.Failed)
	require.Equal(t, "error", s.Reason)
}

func TestPageScriptDoneDuringStallPanel(t *testing.T) {
	run := runPageScript(t, "works", true,
		adv(25000, true), adv(12000, false), snapAt("stalled"),
		step{"op": "done"}, snapAt("done"),
		step{"op": "click", "id": "apx-retry"}, step{"op": "click", "id": "slow-retry"},
		adv(60000, false), snapAt("later"),
		step{"op": "fail", "reason": "submit-error"}, snapAt("submit failed"),
		step{"op": "click", "id": "apx-retry"},
	)
	require.True(t, run.snap(t, "stalled").Failed)
	for _, l := range []string{"done", "later"} {
		s := run.snap(t, l)
		require.False(t, s.Failed || s.Slow || s.Intro, l)
		require.True(t, s.Checking && s.Verifying, l)
		require.Equal(t, []bool{true, true, true}, s.RetryDisabled, l)
	}
	s := run.snap(t, "submit failed")
	require.True(t, s.Failed)
	require.Equal(t, "submit-error", s.Reason)
	require.Equal(t, []bool{false, false, false}, s.RetryDisabled)
	require.Equal(t, 1, run.Reloads, "disabled Retry clicks don't reload; the re-enabled one does")
}

func TestPageScriptExplicitFailIsFinal(t *testing.T) {
	run := runPageScript(t, "works", true,
		adv(3000, true), step{"op": "fail", "reason": "exception"}, adv(5000, true), snapAt("after"),
		step{"op": "click", "id": "apx-retry"},
	)
	s := run.snap(t, "after")
	require.True(t, s.Failed)
	require.Equal(t, "exception", s.Reason)
	require.Equal(t, 1, run.Reloads)
}

// Same cheap ES5 guard as pow.js, applied to the page's inline script.
func TestPageScriptIsES5(t *testing.T) {
	code := regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(pageInlineScript(t, renderPage("T", 8, "/v", "/", 0)), "")
	for _, bad := range []*regexp.Regexp{
		regexp.MustCompile(`=>`), regexp.MustCompile(`\b(const|let|async|await|class|of)\s`),
		regexp.MustCompile("`"), regexp.MustCompile(`\.\.\.`),
		regexp.MustCompile(`\b(Promise|TextEncoder|subtle|fetch)\b`),
	} {
		require.Nil(t, bad.FindStringIndex(code), "challenge.html inline script must stay ES5: found %s", bad)
	}
	require.False(t, strings.Contains(code, ".hidden ="), "use the hidden attribute, not the property")
}

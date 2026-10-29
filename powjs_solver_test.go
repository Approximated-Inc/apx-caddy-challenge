package apxchallenge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// powJSHarness runs assets/pow.js in a Node vm with a fake DOM. The fake
// Worker evaluates the Blob source in its own vm context, so the worker path
// and its SHA-256 code run for real. argv: pow.js path, JSON request.
const powJSHarness = `
var vm = require("vm"), fs = require("fs");
var src = fs.readFileSync(process.argv[2], "utf8");
var req = JSON.parse(process.argv[3]);
var out = { mode: req.mode, hooks: [], workers: 0, digests: {}, lzb: {}, mainSlices: 0, progress: [] };
var t0 = Date.now();
var finished = false;
function finish() {
  if (finished) return;
  finished = true;
  process.stdout.write(JSON.stringify(out));
  process.exit(0);
}
setTimeout(finish, 20000);

var form = {
  elements: { challenge: { value: req.challenge }, solution: { value: "" } },
  getAttribute: function (n) { return n === "data-difficulty" ? String(req.difficulty) : null; },
  submit: function () { out.ms = Date.now() - t0; out.solution = form.elements.solution.value; out.hooks.push("submit"); finish(); }
};
if (req.mode !== "no-dataset") form.dataset = { difficulty: String(req.difficulty) };

var blobs = {}, nblob = 0;
var win = {
  setTimeout: setTimeout, clearTimeout: clearTimeout,
  document: {
    // pow.js reads this once per main-thread slice, never in the worker.
    get hidden() { out.mainSlices++; return false; },
    getElementById: function (id) { return req.mode === "no-form" ? null : (id === "apx-challenge" ? form : null); }
  },
  apxChallengeFail: function (r) { out.hooks.push("fail:" + r); if (req.mode === "no-form") finish(); },
  apxChallengeDone: function () { out.hooks.push("done"); },
  apxChallengeProgress: function (n) { out.progress.push(n); }
};
win.window = win;

if (req.mode.indexOf("worker") === 0) {
  win.Blob = function (parts) { this.src = parts.join(""); };
  win.URL = {
    createObjectURL: function (b) { var k = "blob:" + (++nblob); blobs[k] = b.src; return k; },
    revokeObjectURL: function (k) { delete blobs[k]; }
  };
  win.Worker = function (url) {
    out.workers++;
    if (req.mode === "worker-throws") throw new Error("SecurityError: refused by CSP");
    var self = this, ctx = { setTimeout: setTimeout };
    ctx.self = ctx;
    ctx.postMessage = function (m) { setImmediate(function () { if (!self.dead && self.onmessage) self.onmessage({ data: m }); }); };
    this.terminate = function () { self.dead = true; out.hooks.push("terminate"); };
    this.postMessage = function (m) {
      setImmediate(function () {
        if (req.mode === "worker-error") { self.onerror({ message: "blocked", preventDefault: function () {} }); return; }
        if (req.mode === "worker-silent") return;
        ctx.onmessage({ data: m });
      });
    };
    vm.createContext(ctx);
    vm.runInContext(blobs[url], ctx);
    var core = ctx.powCore();
    (req.inputs || []).forEach(function (s) { out.digests[s] = core.sha256Hex(s); });
    (req.words || []).forEach(function (h) {
      var w = [];
      for (var i = 0; i < 64; i += 8) w.push(parseInt(h.slice(i, i + 8), 16) | 0);
      out.lzb[h] = core.lzb(w);
    });
  };
}

vm.createContext(win);
vm.runInContext(src, win);
`

func runPowJS(t *testing.T, req map[string]any) map[string]any {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH")
	}
	dir := t.TempDir()
	h := filepath.Join(dir, "harness.js")
	require.NoError(t, os.WriteFile(h, []byte(powJSHarness), 0o600))
	p := filepath.Join(dir, "pow.js")
	require.NoError(t, os.WriteFile(p, []byte(powJS), 0o600))
	b, err := json.Marshal(req)
	require.NoError(t, err)
	cmd := exec.Command(node, h, p, string(b))
	cmd.Dir = dir
	raw, err := cmd.Output()
	if ee, ok := err.(*exec.ExitError); ok {
		t.Fatalf("node failed: %v\n%s", err, ee.Stderr)
	}
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out), string(raw))
	return out
}

func hooksOf(out map[string]any) []string {
	var hs []string
	for _, h := range out["hooks"].([]any) {
		hs = append(hs, h.(string))
	}
	return hs
}

// The JS SHA-256 must match Go byte for byte, including UTF-8 and every
// padding boundary (55/56/63/64/65 bytes and the 2-block tail case).
func TestPowJSSha256MatchesGo(t *testing.T) {
	tok := IssueChallenge("secret", "203.0.113.9", "/a/deep/link?x=1", time.Now().Add(time.Minute))
	inputs := []string{"", "abc", "héllo ✓ 🙂.42", tok + ".123456789",
		strings.Repeat("a", 55), strings.Repeat("a", 56), strings.Repeat("a", 63),
		strings.Repeat("a", 64), strings.Repeat("a", 65), strings.Repeat("b", 119),
		strings.Repeat("b", 120), strings.Repeat("c", 1000)}
	words := []string{
		strings.Repeat("0", 64),
		"00000000" + "00000000" + "0001ffff" + strings.Repeat("f", 40),
		"00000000" + "80000000" + strings.Repeat("0", 48),
		"0000ffff" + strings.Repeat("0", 56),
		"7fffffff" + strings.Repeat("f", 56),
		"ffffffff" + strings.Repeat("f", 56),
	}
	out := runPowJS(t, map[string]any{"mode": "worker", "challenge": "x", "difficulty": 1, "inputs": inputs, "words": words})
	digests := out["digests"].(map[string]any)
	for _, in := range inputs {
		sum := sha256.Sum256([]byte(in))
		require.Equal(t, hex.EncodeToString(sum[:]), digests[in], "input %q", in)
	}
	// Leading-zero count across word boundaries, as proof_of_work.go counts it.
	lzb := out["lzb"].(map[string]any)
	for _, h := range words {
		b, err := hex.DecodeString(h)
		require.NoError(t, err)
		n := 0
		for _, x := range b {
			if x == 0 {
				n += 8
				continue
			}
			n += bits.LeadingZeros8(x)
			break
		}
		require.EqualValues(t, n, lzb[h], "words %s", h)
	}
}

// Each path must find the same first solution Go's SolvePoW finds (proves the
// leading-zero-bit count matches) and submit it after calling apxChallengeDone.
func TestPowJSSolvesOnEveryPath(t *testing.T) {
	const d = 12
	cases := []struct {
		mode      string
		challenge string
		worker    bool // the worker supplied the solution: the main thread never searched
	}{
		{"main", IssueChallenge("secret", "198.51.100.7", "/", time.Now().Add(time.Minute)), false},
		{"no-dataset", "short-challenge", false},
		{"worker", IssueChallenge("secret", "198.51.100.7", "/x", time.Now().Add(time.Minute)), true},
		{"worker", "ünïcode-chållenge", true},
		{"worker-throws", "fallback-on-throw", false},
		{"worker-error", "fallback-on-onerror", false},
		{"worker-silent", "fallback-on-no-ready", false},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			out := runPowJS(t, map[string]any{"mode": tc.mode, "challenge": tc.challenge, "difficulty": d})
			sol, _ := out["solution"].(string)
			require.NotEmpty(t, sol, "no submit: %v", out)
			require.True(t, VerifyPoW(tc.challenge, sol, d))
			require.Equal(t, SolvePoW(tc.challenge, d), sol)
			hooks := hooksOf(out)
			require.Equal(t, "submit", hooks[len(hooks)-1])
			require.Equal(t, "done", hooks[len(hooks)-2])
			for _, h := range hooks {
				require.False(t, strings.HasPrefix(h, "fail:"), "unexpected %s", h)
			}
			if strings.HasPrefix(tc.mode, "worker") {
				require.EqualValues(t, 1, out["workers"])
			}
			if tc.mode == "worker-error" || tc.mode == "worker-silent" {
				require.Contains(t, hooks, "terminate")
			}
			if tc.worker {
				require.EqualValues(t, 0, out["mainSlices"], "main thread searched; worker solution was discarded")
			} else {
				require.Greater(t, out["mainSlices"].(float64), 0.0)
				// Main thread reports progress every slice, ending at the solution.
				prog := out["progress"].([]any)
				require.NotEmpty(t, prog)
				n, _ := strconv.Atoi(sol)
				require.EqualValues(t, n+1, prog[len(prog)-1])
			}
			if tc.mode == "worker-error" {
				// onerror falls back at once, not after the 1.5s ready watchdog.
				require.Less(t, out["ms"].(float64), 1000.0)
			}
		})
	}
}

// The worker posts progress (first after its first 4096-attempt chunk, then at
// most every 250 ms) and the page forwards it to apxChallengeProgress.
func TestPowJSWorkerReportsProgress(t *testing.T) {
	const d = 16
	ch := ""
	for i := 0; ; i++ {
		c := "progress-" + strconv.Itoa(i)
		if n, _ := strconv.Atoi(SolvePoW(c, d)); n > 4096 {
			ch = c
			break
		}
	}
	out := runPowJS(t, map[string]any{"mode": "worker", "challenge": ch, "difficulty": d})
	require.Equal(t, SolvePoW(ch, d), out["solution"])
	require.EqualValues(t, 0, out["mainSlices"])
	prog := out["progress"].([]any)
	require.NotEmpty(t, prog)
	require.EqualValues(t, 4096, prog[0])
}

// A long main-thread solve reports progress once per time slice.
func TestPowJSMainThreadReportsProgressPerSlice(t *testing.T) {
	const d = 16
	ch := ""
	for i := 0; ; i++ {
		c := "slices-" + strconv.Itoa(i)
		if n, _ := strconv.Atoi(SolvePoW(c, d)); n > 250000 {
			ch = c
			break
		}
	}
	out := runPowJS(t, map[string]any{"mode": "main", "challenge": ch, "difficulty": d})
	require.Equal(t, SolvePoW(ch, d), out["solution"])
	slices := int(out["mainSlices"].(float64))
	require.GreaterOrEqual(t, slices, 2, "solve should span several 50 ms slices")
	prog := out["progress"].([]any)
	require.Len(t, prog, slices)
	for k := 1; k < len(prog); k++ {
		require.Greater(t, prog[k].(float64), prog[k-1].(float64))
	}
}

func TestPowJSFailHookWithoutForm(t *testing.T) {
	out := runPowJS(t, map[string]any{"mode": "no-form", "challenge": "x", "difficulty": 4})
	require.Equal(t, []string{"fail:no-form"}, hooksOf(out))
}

// Cheap guard against ES2015+ syntax creeping back in (old TV browsers).
func TestPowJSIsES5(t *testing.T) {
	code := regexp.MustCompile(`(?m)//.*$`).ReplaceAllString(powJS, "")
	for _, bad := range []*regexp.Regexp{
		regexp.MustCompile(`=>`), regexp.MustCompile(`\b(const|let|async|await|class|of)\s`),
		regexp.MustCompile("`"), regexp.MustCompile(`\.\.\.`),
		regexp.MustCompile(`\b(Promise|TextEncoder|subtle|fetch)\b`),
	} {
		require.Nil(t, bad.FindStringIndex(code), "pow.js must stay ES5: found %s", bad)
	}
}

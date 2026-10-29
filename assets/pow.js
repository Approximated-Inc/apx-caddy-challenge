// Reads the challenge from the form's hidden input, brute-forces a SHA-256
// leading-zero-bit solution, fills the hidden solution field, and submits the
// form natively so the browser follows the server's 303 redirect (sets the
// cookie AND honors the original deep-link).
// The hash input MUST be `challenge + "." + i` to match the Go verifier.
//
// ES5 only (old TV browsers): no crypto.subtle, TextEncoder or Promise. The
// solve runs in a Blob worker when one starts, else in time-sliced batches on
// the main thread. Errors go to window.apxChallengeFail(reason).
(function () {
  var win = window;
  var done = false;

  function fail(reason) {
    try {
      if (typeof win.apxChallengeFail === "function") win.apxChallengeFail(reason);
    } catch (e) {}
  }

  // Self-contained: serialized into the worker with toString().
  function powCore() {
    var K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    var IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var W = typeof Int32Array !== "undefined" ? new Int32Array(64) : new Array(64);
    var buf = new Array(128);
    var H = new Array(8);

    // W[0..15] holds the block; H is updated in place.
    function compress(H) {
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      var j, x, y, t1, t2;
      for (j = 16; j < 64; j++) {
        x = W[j - 15];
        y = W[j - 2];
        W[j] = (W[j - 16] + (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) +
          W[j - 7] + (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10))) | 0;
      }
      for (j = 0; j < 64; j++) {
        t1 = (h + (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) +
          ((e & f) ^ (~e & g)) + K[j] + W[j]) | 0;
        t2 = ((((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) +
          ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0;
        d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }

    function load(bytes, off) {
      for (var j = 0; j < 16; j++) {
        var o = off + j * 4;
        W[j] = (bytes[o] << 24) | (bytes[o + 1] << 16) | (bytes[o + 2] << 8) | bytes[o + 3];
      }
    }

    // Hashes the whole 64-byte blocks of the UTF-8 prefix once (midstate).
    function prepare(prefix) {
      var s = unescape(encodeURIComponent(prefix));
      var codes = [], i;
      for (i = 0; i < s.length; i++) codes.push(s.charCodeAt(i));
      var full = codes.length - (codes.length % 64);
      var state = IV.slice(0);
      for (i = 0; i < full; i += 64) {
        load(codes, i);
        compress(state);
      }
      return { state: state, tail: codes.slice(full), len: codes.length };
    }

    // SHA-256 of prefix + suffix (suffix ASCII). Returns 8 signed int words.
    function digest(p, suffix) {
      var tail = p.tail, tl = tail.length, sl = suffix.length, n = tl + sl, i;
      for (i = 0; i < tl; i++) buf[i] = tail[i];
      for (i = 0; i < sl; i++) buf[tl + i] = suffix.charCodeAt(i);
      buf[n] = 0x80;
      var end = n + 9 > 64 ? 128 : 64;
      for (i = n + 1; i < end - 4; i++) buf[i] = 0;
      var bits = (p.len + sl) * 8;
      buf[end - 4] = (bits >>> 24) & 255;
      buf[end - 3] = (bits >>> 16) & 255;
      buf[end - 2] = (bits >>> 8) & 255;
      buf[end - 1] = bits & 255;
      for (i = 0; i < 8; i++) H[i] = p.state[i];
      for (i = 0; i < end; i += 64) {
        load(buf, i);
        compress(H);
      }
      return H;
    }

    // Same count as proof_of_work.go leadingZeroBits (byte-wise == word-wise).
    function lzb(H) {
      var n = 0;
      for (var i = 0; i < 8; i++) {
        var w = H[i] >>> 0;
        if (w === 0) { n += 32; continue; }
        while ((w & 0x80000000) === 0) { n++; w = w << 1; }
        break;
      }
      return n;
    }

    // First i in [start, start+count) whose hash meets difficulty, else -1.
    function search(p, difficulty, start, count) {
      for (var i = start; i < start + count; i++) {
        if (lzb(digest(p, String(i))) >= difficulty) return i;
      }
      return -1;
    }

    function hex(H) {
      var out = "";
      for (var i = 0; i < 8; i++) {
        var s = (H[i] >>> 0).toString(16);
        while (s.length < 8) s = "0" + s;
        out += s;
      }
      return out;
    }

    return {
      prepare: prepare,
      digest: digest,
      lzb: lzb,
      search: search,
      sha256Hex: function (s) { return hex(digest(prepare(s), "")); }
    };
  }

  try {
    var form = document.getElementById("apx-challenge");
    if (!form || !form.elements) { fail("no-form"); return; }
    var chEl = form.elements.challenge;
    var solEl = form.elements.solution;
    if (!chEl || !solEl) { fail("no-form"); return; }
    var diffAttr = form.dataset ? form.dataset.difficulty : form.getAttribute("data-difficulty");
    var difficulty = parseInt(diffAttr, 10);
    if (isNaN(difficulty)) { fail("no-difficulty"); return; }
    var prefix = chEl.value + ".";

    var submit = function (solution) {
      if (done) return;
      done = true;
      try {
        solEl.value = solution;
        try {
          if (typeof win.apxChallengeDone === "function") win.apxChallengeDone();
        } catch (e) {}
        form.submit();
      } catch (e) {
        fail("submit-error");
      }
    };

    var mainThread = function () {
      if (done) return;
      var core, p, i = 0;
      try {
        core = powCore();
        p = core.prepare(prefix);
      } catch (e) {
        fail("exception");
        return;
      }
      var step = function () {
        if (done) return;
        try {
          // Hidden tabs clamp timers to ~1/s, so do more per slice there.
          var stop = new Date().getTime() + (document.hidden ? 500 : 50);
          do {
            var r = core.search(p, difficulty, i, 1024);
            if (r >= 0) { submit(String(r)); return; }
            i += 1024;
          } while (new Date().getTime() < stop);
          setTimeout(step, 0);
        } catch (e) {
          fail("exception");
        }
      };
      step();
    };

    // Returns false when no worker could be started (caller runs mainThread).
    var startWorker = function () {
      if (typeof win.Worker !== "function" && typeof win.Worker !== "object") return false;
      if (!win.Worker || typeof win.Blob === "undefined") return false;
      var U = win.URL || win.webkitURL;
      if (!U || typeof U.createObjectURL !== "function") return false;

      var src = powCore.toString() +
        "\nvar c = powCore();" +
        "\nself.onmessage = function (e) {" +
        "\n  var m = String(e.data), k = m.indexOf('|');" +
        "\n  var d = parseInt(m.slice(0, k), 10), p = c.prepare(m.slice(k + 1));" +
        "\n  self.postMessage('ready');" +
        "\n  for (var i = 0; ; i += 65536) {" +
        "\n    var r = c.search(p, d, i, 65536);" +
        "\n    if (r >= 0) { self.postMessage('s:' + r); return; }" +
        "\n  }" +
        "\n};";
      var w, url, readyTimer, abandoned = false;
      var abandon = function () {
        if (abandoned) return;
        abandoned = true;
        clearTimeout(readyTimer);
        try { w.terminate(); } catch (e) {}
        try { U.revokeObjectURL(url); } catch (e) {}
        mainThread();
      };
      try {
        url = U.createObjectURL(new Blob([src], { type: "text/javascript" }));
        w = new win.Worker(url);
      } catch (e) {
        // Constructor refused (e.g. CSP without worker-src).
        try { if (url) U.revokeObjectURL(url); } catch (e2) {}
        return false;
      }
      w.onerror = function (e) {
        if (e && e.preventDefault) e.preventDefault();
        abandon();
      };
      w.onmessage = function (e) {
        if (abandoned) return;
        var m = String(e.data);
        if (m === "ready") { clearTimeout(readyTimer); return; }
        if (m.slice(0, 2) !== "s:") return;
        var s = m.slice(2);
        // One hash on the main thread guards against a broken worker.
        var core = powCore();
        if (core.lzb(core.digest(core.prepare(prefix), s)) < difficulty) { abandon(); return; }
        abandoned = true;
        try { w.terminate(); } catch (e2) {}
        try { U.revokeObjectURL(url); } catch (e3) {}
        submit(s);
      };
      // A worker blocked without an error event never says ready.
      readyTimer = setTimeout(abandon, 1500);
      w.postMessage(difficulty + "|" + prefix);
      return true;
    };

    var started = false;
    try {
      started = startWorker();
    } catch (e) {
      started = false;
    }
    if (!started) mainThread();
  } catch (e) {
    fail("exception");
  }
})();

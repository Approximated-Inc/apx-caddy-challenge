/*
 * Approximated first-party Edge Verify widget.
 *
 * Served from the customer's own domain by the edge (embedded in the Go binary,
 * endpoint paths substituted server-side). It is the in-house alternative to a
 * third-party CAPTCHA/Turnstile: it transparently proves the visitor ran a real
 * browser and injects a signed, short-lived token into every form so the edge
 * can gate submissions.
 *
 * Flow (all same-origin, no cookies, no storage, no third-party requests):
 *   1. POST {{CHALLENGE_PATH}}  -> { challenge, difficulty }
 *   2. Solve proof-of-work in a Web Worker: find `solution` such that
 *      SHA-256(challenge + "." + solution) has >= difficulty LEADING ZERO BITS.
 *      The hash input is byte-identical to the Go verifier (proof_of_work.go).
 *   3. POST {{TOKEN_PATH}} (urlencoded: challenge, solution, probes) -> { token, expires_in }
 *   4. Inject <input type="hidden" name="_apx_verify_token" value=token> into every
 *      <form> (now and, via MutationObserver, any added later by SPAs).
 *   5. Refresh the token before it expires.
 *
 * window.apxVerify.getToken() returns the current token (or null) so fetch/JSON
 * submitters can send it in the `X-Apx-Verify-Token` request header.
 *
 * Dependency-free vanilla JS, no build step.
 */
(function () {
  "use strict";

  var CHALLENGE_PATH = "{{CHALLENGE_PATH}}";
  var TOKEN_PATH = "{{TOKEN_PATH}}";
  var FIELD_NAME = "_apx_verify_token";
  var HEADER_NAME = "X-Apx-Verify-Token";

  var startedAt = now();
  var currentToken = null;
  var interactions = 0;
  var refreshTimer = null;

  // --- public API ---------------------------------------------------------
  window.apxVerify = {
    getToken: function () {
      return currentToken;
    },
  };

  // --- probes -------------------------------------------------------------
  function now() {
    return typeof performance !== "undefined" && performance.now
      ? performance.now()
      : Date.now();
  }

  // Passively count real user input so headless drivers that never interact
  // look distinct from humans. Never blocks or preventDefaults anything.
  var INTERACTION_EVENTS = [
    "pointerdown",
    "pointermove",
    "keydown",
    "input",
    "touchstart",
    "mousemove",
  ];
  function bumpInteraction() {
    interactions++;
  }
  for (var i = 0; i < INTERACTION_EVENTS.length; i++) {
    try {
      document.addEventListener(INTERACTION_EVENTS[i], bumpInteraction, {
        passive: true,
        capture: true,
      });
    } catch (e) {
      document.addEventListener(INTERACTION_EVENTS[i], bumpInteraction, true);
    }
  }

  // APIs a genuine modern browser exposes; absences are a bot tell. Reported as
  // signal only (server scores them) — never used to block on the client.
  //
  // Only APIs that are UNIVERSAL across real interactive browsers belong here:
  // a platform-legitimate absence would be a false bot tell that, under a low
  // scoring threshold, blocks real users. Deliberately excluded: Notification
  // (undefined in normal iOS Safari and most in-app WebViews) and localStorage
  // (throws/absent when storage access is blocked) — both are commonly missing
  // on real devices and were poor signals.
  function missingAPIs() {
    var missing = [];
    var checks = {
      Promise: typeof Promise !== "undefined",
      fetch: typeof fetch !== "undefined",
      Worker: typeof Worker !== "undefined",
      MutationObserver: typeof MutationObserver !== "undefined",
      IntersectionObserver: typeof IntersectionObserver !== "undefined",
      requestAnimationFrame: typeof requestAnimationFrame !== "undefined",
      Intl: typeof Intl !== "undefined",
      WebGLRenderingContext: typeof WebGLRenderingContext !== "undefined",
    };
    for (var k in checks) {
      if (checks.hasOwnProperty(k) && !checks[k]) missing.push(k);
    }
    return missing;
  }

  function collectProbes() {
    return {
      fill_ms: Math.round(now() - startedAt),
      interactions: interactions,
      webdriver: !!(navigator && navigator.webdriver),
      missing_apis: missingAPIs(),
    };
  }

  // --- proof of work (Web Worker from an inline Blob URL) -----------------
  // The worker searches i = 0, 1, 2, ... computing SHA-256(challenge + "." + i)
  // and returns the first i whose digest has >= difficulty leading zero bits.
  // leadingZeroBits mirrors proof_of_work.go: whole zero bytes count 8 each,
  // then Math.clz32(b) - 24 gives the leading zeros of the first non-zero byte
  // (clz32 treats b as a 32-bit int, so its 24 high bits are always zero).
  var WORKER_SRC = [
    "self.onmessage = function (ev) {",
    "  var challenge = ev.data.challenge;",
    "  var difficulty = ev.data.difficulty | 0;",
    "  var enc = new TextEncoder();",
    "  function lzBits(bytes) {",
    "    var n = 0;",
    "    for (var j = 0; j < bytes.length; j++) {",
    "      var b = bytes[j];",
    "      if (b === 0) { n += 8; continue; }",
    "      n += Math.clz32(b) - 24;",
    "      break;",
    "    }",
    "    return n;",
    "  }",
    "  function loop(i) {",
    "    // Chunk the search so postMessage/terminate can still be delivered.",
    "    var end = i + 1000;",
    "    var step = function () {",
    "      if (i >= end) { setTimeout(function () { loop(i); }, 0); return; }",
    "      var input = enc.encode(challenge + \".\" + i);",
    "      crypto.subtle.digest('SHA-256', input).then(function (buf) {",
    "        var bytes = new Uint8Array(buf);",
    "        if (lzBits(bytes) >= difficulty) {",
    "          self.postMessage({ solution: String(i) });",
    "          return;",
    "        }",
    "        i++;",
    "        step();",
    "      });",
    "    };",
    "    step();",
    "  }",
    "  if (difficulty <= 0) { self.postMessage({ solution: '0' }); return; }",
    "  loop(0);",
    "};",
  ].join("\n");

  function solvePoW(challenge, difficulty) {
    return new Promise(function (resolve, reject) {
      var url;
      var worker;
      try {
        var blob = new Blob([WORKER_SRC], { type: "application/javascript" });
        url = URL.createObjectURL(blob);
        worker = new Worker(url);
      } catch (e) {
        // No Worker/Blob support: fall back to a main-thread solve so the token
        // can still be minted (rare; keeps forms usable everywhere).
        solveInline(challenge, difficulty).then(resolve, reject);
        return;
      }
      worker.onmessage = function (ev) {
        cleanup();
        resolve(ev.data.solution);
      };
      worker.onerror = function (err) {
        cleanup();
        reject(err);
      };
      function cleanup() {
        try { worker.terminate(); } catch (e) {}
        try { URL.revokeObjectURL(url); } catch (e) {}
      }
      worker.postMessage({ challenge: challenge, difficulty: difficulty });
    });
  }

  // Main-thread fallback solver (same construction and bit count as the worker).
  function solveInline(challenge, difficulty) {
    if (difficulty <= 0) return Promise.resolve("0");
    var enc = new TextEncoder();
    function lzBits(bytes) {
      var n = 0;
      for (var j = 0; j < bytes.length; j++) {
        var b = bytes[j];
        if (b === 0) { n += 8; continue; }
        n += Math.clz32(b) - 24;
        break;
      }
      return n;
    }
    return new Promise(function (resolve) {
      var i = 0;
      function loop() {
        var end = i + 500;
        function step() {
          if (i >= end) { setTimeout(loop, 0); return; }
          crypto.subtle
            .digest("SHA-256", enc.encode(challenge + "." + i))
            .then(function (buf) {
              if (lzBits(new Uint8Array(buf)) >= difficulty) {
                resolve(String(i));
                return;
              }
              i++;
              step();
            });
        }
        step();
      }
      loop();
    });
  }

  // --- token lifecycle ----------------------------------------------------
  function postForm(path, fields) {
    var body = Object.keys(fields)
      .map(function (k) {
        return encodeURIComponent(k) + "=" + encodeURIComponent(fields[k]);
      })
      .join("&");
    return fetch(path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body,
    });
  }

  function fetchChallenge() {
    return fetch(CHALLENGE_PATH, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "",
    }).then(function (res) {
      if (!res.ok) throw new Error("challenge http " + res.status);
      return res.json();
    });
  }

  function obtainToken() {
    return fetchChallenge()
      .then(function (data) {
        var challenge = data.challenge;
        var difficulty = data.difficulty | 0;
        return solvePoW(challenge, difficulty).then(function (solution) {
          return postForm(TOKEN_PATH, {
            challenge: challenge,
            solution: solution,
            probes: JSON.stringify(collectProbes()),
          });
        });
      })
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        if (!data || !data.token) {
          // Refusal payload is { error, reason } — leave forms unmodified.
          throw new Error("token refused: " + (data && data.reason));
        }
        currentToken = data.token;
        injectAll();
        scheduleRefresh(data.expires_in);
        return currentToken;
      })
      .catch(function (e) {
        // Fail open: a broken widget must never wedge a real customer's forms.
        if (window.console && console.debug) console.debug("apxVerify:", e);
      });
  }

  function scheduleRefresh(expiresIn) {
    if (refreshTimer) clearTimeout(refreshTimer);
    var seconds = typeof expiresIn === "number" && expiresIn > 0 ? expiresIn : 600;
    // Refresh a bit early (30s margin, clamped) so a submit never races expiry.
    var ms = Math.max((seconds - 30) * 1000, 5000);
    refreshTimer = setTimeout(obtainToken, ms);
  }

  // --- form injection -----------------------------------------------------
  function injectInto(form) {
    if (!form || form.nodeName !== "FORM") return;
    var input = form.querySelector('input[name="' + FIELD_NAME + '"]');
    if (!input) {
      input = document.createElement("input");
      input.type = "hidden";
      input.name = FIELD_NAME;
      form.appendChild(input);
    }
    input.value = currentToken || "";
  }

  function injectAll() {
    if (!currentToken) return;
    var forms = document.getElementsByTagName("form");
    for (var i = 0; i < forms.length; i++) injectInto(forms[i]);
  }

  function watchForForms() {
    if (typeof MutationObserver === "undefined") return;
    var mo = new MutationObserver(function (mutations) {
      if (!currentToken) return;
      for (var m = 0; m < mutations.length; m++) {
        var added = mutations[m].addedNodes;
        for (var n = 0; n < added.length; n++) {
          var node = added[n];
          if (node.nodeType !== 1) continue;
          if (node.nodeName === "FORM") injectInto(node);
          if (node.getElementsByTagName) {
            var nested = node.getElementsByTagName("form");
            for (var q = 0; q < nested.length; q++) injectInto(nested[q]);
          }
        }
      }
    });
    mo.observe(document.documentElement || document, {
      childList: true,
      subtree: true,
    });
  }

  // --- boot ---------------------------------------------------------------
  function boot() {
    watchForForms();
    obtainToken();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();

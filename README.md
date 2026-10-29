# apx-caddy-challenge

Interactive proof-of-work (PoW) challenge handler for Caddy, used by the
Approximated `challenge` defense effect. Serves a JS PoW page to suspicious
traffic; a solved, HMAC-signed cookie lets the client through for 10 minutes.
Stateless server-side (the cookie is the proof — no challenge table).

## Modules

- App `apx_challenge` — holds `difficulty`, the per-cluster HMAC `secret`
  (supplied inline in config, not an env var), and the `verify_path`.
- HTTP handler `http.handlers.apx_challenge` — invoked by the per-dimension
  challenge routes (ip/sni/path) + the verify route that Phoenix config-gen
  emits when the cluster image carries the `challenge` token.

## How it works

1. A request matched by a `challenge` route hits the handler. If it carries a
   valid `apx-challenge` cookie (HMAC over `{exp, /24-or-/64 prefix}`, 10-min
   TTL by default; see "Pass-cookie policy" below), it's forwarded upstream
   (`passed_recently`).
2. Otherwise the handler serves a self-contained HTML page whose JS brute-forces
   a SHA-256 leading-zero-bits PoW (`difficulty` bits, default 16), then submits
   the solution via a native form POST to `verify_path`.
3. The verify endpoint re-checks the signed challenge token (signature, expiry,
   client-prefix) and the PoW (against the server's configured difficulty), sets
   the `apx-challenge` cookie, and 303-redirects to the original URL.
4. Non-browser clients (CORS fetches / non-HTML Accept) get `429
   {"error":"challenge_required","retry_after":30}`; WebSocket/SSE get `503
   Retry-After: 30`.

The handler sets the `apx_challenge_outcome` request var
(`issued | passed | passed_fallback | passed_recently | failed`) for the
apx-caddy-stats recorder (Phase 9c). `passed_fallback` appears only when the
render-check fallback below is on. The fallback pixel request sets no outcome.

## Config (emitted by Phoenix — not hand-written)

    "apps": { "apx_challenge": {
      "difficulty": 16,
      "secret": "<per-cluster secret>",
      "verify_path": "/__apx_challenge/verify"
    } }

Routes use `{"handler": "apx_challenge"}` (terminal). The verify route is emitted
first so the solution POST always reaches the handler.

### Pass-cookie policy (optional)

These keys are optional. Absent or `0`/`false`, the handler behaves exactly as
before: a 10-minute, non-rolling cookie bound to the client /24 (IPv4) or /64
(IPv6), with the payload `{e, p}`. Provision rejects out-of-range values, so a
bad value fails the config load rather than silently changing the cookie.

| Key | Default | Allowed | Effect |
|-----|---------|---------|--------|
| `pass_idle_ttl_seconds` | `600` | 60–86400 | Cookie lifetime from the solve or the last renewal. |
| `pass_max_ttl_seconds` | `0` (= idle, no rolling) | 0, or idle–604800 | Absolute lifetime from the original solve. Rolling renewal is on only when this is larger than the idle TTL. |
| `pass_ipv4_prefix` | `24` | 16–32 | IPv4 network width the cookie is bound to. |
| `pass_ipv6_prefix` | `64` | 32–128 | IPv6 network width the cookie is bound to. |
| `pass_bind_user_agent` | `false` | bool | Also bind the cookie to a hash of the `User-Agent` header. |

**Rolling renewal.** When `pass_max_ttl_seconds` > idle TTL, a request with a
valid cookie that has less than half the idle TTL left gets a fresh cookie
(same `Secure; HttpOnly; SameSite=Lax; Path=/`, `Max-Age` = new expiry) with
expiry `min(now + idle, issued_at + max)`. Under rolling, the cookie carries
`i`, the issue time of the challenge that was solved (not the verify time),
and renewal never moves it. An active visitor is re-challenged once per
`pass_max_ttl_seconds` instead of once per idle TTL, and an idle one once the
idle TTL lapses. Verify also rejects a cookie once `i + pass_max_ttl_seconds`
has passed, so lowering the cap takes effect at once rather than at each
cookie's `exp`. Cookies without `i` (all cookies before this change, and any
minted while rolling was off) are accepted until their own `exp` and never
renewed, so their holders solve once more after rolling is turned on.
Renewal adds a `Set-Cookie` to the proxied upstream response when it fires.

**Challenge binding and single use.** Under any non-default policy, the
challenge token is bound to the same prefix width and (under UA binding) the
same UA hash as the cookie it earns, and a solved challenge is single-use per
machine (the shared bounded nonce LRU also used by Edge Verify, kept at
process level so a config reload does not forget spent solves). The token also
carries its issue time (`i`), which becomes the cookie's issued-at; tokens
without it (default policy, or minted by an older machine) fall back to
`exp - 5 min`. One solve therefore mints one cookie, for the address and UA
that fetched the page. A replayed solve fails like any other verify: a bare
403 for scripts, and for a browser form post a counted failure in the tries
cookie plus a redirect to a fresh challenge (the explanation page at the
threshold). A solve is recorded as spent only after its token and PoW verify.
Single use is per machine, not cluster-wide: the same solution posted to
another machine within the token's 5-minute life can mint a second cookie, for
the same prefix and UA. Under the default policy, tokens are byte-identical to
before and verify stays reusable, as it always was.

Security trade-offs:

- **Idle TTL.** Longer means fewer challenges for everyone, and a longer
  window in which a stolen or bot-farmed cookie works. A bot that solves one
  challenge gets the full idle TTL either way.
- **Max TTL (rolling).** Renewal only extends cookies that are being used, so a
  harvested cookie still dies after the idle TTL unless it keeps being
  replayed, and nothing lives past the cap. But a bot that solves once and
  keeps sending requests also keeps its cookie up to the cap. Pair a long cap
  with a narrow prefix and/or UA binding, and keep the cap modest (hours, not
  days) on routes that see automated abuse. Shared caches in front of the
  cluster could store a renewal `Set-Cookie` on a cacheable upstream response;
  the cookie is still bound to the original prefix (and UA), so this only
  matters for clients sharing that network.
- **Prefix width.** Wider (`/16`, `/48`) survives mobile and CGNAT address
  changes but lets anyone in that network reuse the cookie, including a bot
  farm sharing a cloud provider's range. Narrower (`/32`, `/128`) is tighter
  but re-challenges users whose address changes mid-session (mobile handover,
  privacy addresses on IPv6). Changing a width invalidates outstanding cookies
  once (the stored prefix no longer matches). The challenge token itself stays
  bound to the /24 or /64 between page load and verify.
- **User-Agent binding.** Stops a cookie being reused by a different client
  stack that does not copy the UA, at no cost to a real browser. It is not a
  strong control, since the UA is client-supplied and trivially copied, and a
  browser update mid-session changes the UA and triggers one re-challenge.
  Turning it on invalidates outstanding cookies once (they carry no UA hash);
  turning it off accepts both kinds.

**Rollout.** Caddy strict-unmarshals config at load and at machine boot, so
an image without these keys rejects any config containing a `pass_*` key. The
app must gate emitting them on an image capability. During a mixed deploy,
machines on the old image ignore `u` (they accept a UA-bound cookie from any
UA), ignore `i` (no cap enforcement), and reject /32 or other non-/24 cookies
and challenge tokens (those users are re-challenged when a request lands on an
old machine). Safe order: roll the image fleet-wide first, then turn the keys
on per cluster.

**TLS fingerprint binding is not offered.** JA3/JA4 are computed by the
caddy-l4 fork's `tls` matcher and stored only as layer4 connection vars
(`tls_ja3` / `tls_ja4`). The layer4 route then proxies the connection to the
HTTP server on `127.0.0.1:8443` with PROXY protocol v2, which carries the
client address but not those vars, so nothing in the HTTP request (no
placeholder, header or context value) exposes a fingerprint to this handler.
Binding would need the fingerprint carried across that hop (a custom PROXY v2
TLV written by caddy-l4's proxy handler and read back by an HTTP listener
wrapper into a request var or placeholder), plus an image rollout of both.

### Render-check fallback (on by default)

The challenge answers "is this a browser?", not "is this a human?". Some real
browsers can't run the proof-of-work script (old TV browsers, locked-down
setups, script-blocking extensions). The page also offers a plain HTML form
with a **Continue** button, shown in the `<noscript>` block and in the failure panel (after a stall, timeout or error). It needs no
JavaScript, and it passes only when the visitor behaves like a browser that
renders the page, which simple HTTP clients (curl, scripts, scrapers) don't.

The form and the fallback cookie are added only to challenge responses that
are likely to be displayed (`Accept` contains `text/html`, or
`Sec-Fetch-Dest: document`). A challenged subresource such as `/favicon.ico`,
which older browsers fetch with `Accept: */*` and no `Sec-Fetch-*` headers,
gets the plain challenge page and leaves the fallback cookie alone.

A fallback POST (`mode=fallback`, to `verify_path`) passes only when all hold:

1. **Token.** The form's `fallback` token verifies (HMAC under its own
   `fallback` label, unexpired, 10-minute life), for the same client prefix
   and (under `pass_bind_user_agent`) the same UA as the pass-cookie policy.
2. **Cookie round-trip.** The request carries `__Host-apx-challenge-fallback`
   (Secure, HttpOnly, SameSite=Lax, Path=/, Max-Age 600). It holds a signed
   list of the 4 most recent fallback nonces issued to this browser, so a
   second tab doesn't strand the first; the token's nonce must be in it. A
   pass removes that nonce and clears the cookie once the list is empty.
3. **Render proof.** The page's inline `<style>` gives an element inside the
   form a CSS `background-image` of a 1×1 GIF at
   `verify_path?apx_fallback_pixel=<nonce>.<exp>.<sig>`. The signature covers
   the nonce, the token's expiry and the requester's client prefix (plus the
   UA hash under `pass_bind_user_agent`), so a pixel URL works only until the
   token expires and only from the network (and UA) that loaded the page.
   Anything invalid is a 404 and records nothing (`Cache-Control: no-store`
   throughout). A valid URL always gets the image, but only a request that
   looks like a browser loading an image records the nonce as rendered on
   this machine, until the token's expiry: a GET (never HEAD) that sends
   `Sec-Fetch-Dest: image` when it sends any `Sec-Fetch-*` header, or, from
   browsers without `Sec-Fetch-*`, an `Accept` header naming an `image/`
   type (IE11, older Safari and Firefox all do). The pixel uses the verify path, so the existing verify
   route reaches it (Caddy's `path` matcher ignores the query); no new route
   is needed.
4. **Dwell.** At least `fallback_min_dwell_seconds` since the token was issued.
5. **Single use.** The nonce is claimed (spent) atomically; a nonce already
   claimed fails.
6. **Budget.** Fewer than `fallback_max_per_hour` fallback passes from the
   client prefix in the last hour, on this machine. The prefix is the pass
   policy's width (by default the /24 or /64), so everyone behind one office
   or carrier-NAT /24 shares the budget.

Nothing is recorded until conditions 1–4 hold. The nonce is then claimed
before the budget is charged, so concurrent replays of one nonce lose the
claim and use no budget. A claimed nonce that then finds the budget used up
stays spent; that visitor gets a fresh challenge anyway.

A pass sets the normal `apx-challenge` cookie, but non-rolling (no issued-at,
so it is never renewed) and with `fallback_pass_ttl_seconds` as its lifetime,
sets the outcome `passed_fallback` and continues like a solve (tries counting,
303 to the original URL). Any failure takes the same path as a failed solve:
a 403 for scripts, and for a browser form post a counted failure plus a
redirect to a fresh challenge (the explanation page at the threshold).

| Key | Default | Allowed | Effect |
|-----|---------|---------|--------|
| `fallback_disabled` | `false` | bool | Emergency opt-out. When true: no markup, cookie, pixel or `mode=fallback` handling, and the page is byte-identical to the page before the fallback existed. |
| `fallback_pass_ttl_seconds` | `300`, clamped to the pass idle TTL | 60 to the pass idle TTL | Lifetime of the non-rolling pass cookie a fallback pass earns. Never longer than a solved cookie's idle TTL: a larger explicit value fails provisioning, and the default is lowered to the idle TTL when that is shorter. |
| `fallback_max_per_hour` | `3` | 1–1000 | Fallback passes per client prefix (the pass policy's width, /24 or /64 by default) per hour, per machine. |
| `fallback_min_dwell_seconds` | `2` | 1–60 | Minimum time from page issue to the POST. |

**Per machine, and separate.** Rendered nonces, spent nonces and the hourly
budget live in the fallback's own per-process stores (they survive config
reloads). They are never shared across machines, and never written to the
replay set that Edge Verify and solved challenges use, so fallback traffic
cannot evict those. When the pixel and the POST land on different machines,
the POST finds nothing recorded and fails safely into a fresh challenge; the
visitor tries again. A browser usually sends both over one connection, so
this is rare. The budget is per machine, so a cluster allows up to
`fallback_max_per_hour` × machines per prefix.

**Store bounds.** Each store (rendered nonces, spent nonces, prefixes in the
budget) holds at most 16,384 records; all three full measured about 6.5 MB. Records are
dropped once their token has expired, so the stores only hold the live
10-minute window. Past the cap the record that expires soonest is evicted, so
an expired record always goes before a live one. Every rendered record needs
a fresh challenge page and a pixel GET from the attacker's own prefix, so to
evict a real visitor's render record an attacker has to load about 16,384
challenge pages and pixels within that visitor's 10-minute window on the same
machine (about 27 a second, sustained). The visitor then fails once into a
fresh challenge and can try again. Spent records need a rendered nonce, a
matching cookie and the dwell for each, so evicting one to replay a nonce
within its token's life takes thousands of such attempts.

**Tabs.** The cookie keeps the 4 most recent nonces, so tabs opened one after
another all work. Two tabs whose challenge responses are in flight at the
same time both start from the same cookie, so the later response's cookie
drops the other tab's nonce. That tab's Continue fails once into a fresh
challenge, which then works.

**What it does not stop.** A script written for this page, one that keeps
cookies, reads the CSS, sends a GET for the pixel with browser-like image
headers and waits two seconds, passes, just as a headless browser passes the
proof-of-work. The fallback stops generic HTTP clients (curl, scrapers that
don't load subresources, HEAD probes), and the hourly budget limits how many
cookies one network gets this way. The fallback cookie is non-rolling and
lasts 300 s by default. Under the default pass policy a solved cookie is also
non-rolling and lasts 600 s, so a fallback pass is worth half a solve; under a
rolling policy the gap is larger. Text browsers that ignore CSS (lynx, w3m)
fail it.

**CSP.** The pixel is an image load, so `img-src` must allow the site. Whenever
a cluster has an edge-sequence challenge or a reputation mode of `block` or
`challenge`, the app emits its response-guard route ahead of every challenge
route (it has no matcher). That route sets this CSP on every issued challenge
page, including per-IP ledger and reputation challenges:

    default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'

With no `img-src`, `default-src 'none'` blocks the pixel, so the fallback
always fails there (safely, into a fresh challenge). Only clusters without the
guard (ledger challenges and nothing else) serve the page with no CSP, so the
fallback works there as it is. The app needs to add `img-src 'self'`:

    default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'

No CSP-compatible alternative exists under `default-src 'none'`: every
subresource fetch (images, fonts, frames, stylesheets, prefetch) falls back to
it, and only the form navigation is allowed.

The fallback needs no config: every machine running this image serves it
with the defaults above. All `fallback_*` keys are optional.

**Rollout.** Deploy the image; every machine then serves the fallback, and the
app emits no new key. Before the image rolls out, the app must:

- accept the `passed_fallback` outcome at analytics ingest (Approximated
  PR #442), or those passes are dropped from analytics;
- add `img-src 'self'` to the response-guard CSP (also #442), or the pixel is
  blocked on every cluster that emits the guard and the fallback fails there
  (safely, into a fresh challenge).

The optional keys (`fallback_disabled` and the tuning keys) are rejected by an
older image (Caddy strict-unmarshals config), so the app should emit them only
when it needs them, gated on an image capability like the `pass_*` keys.

## Build (xcaddy — image step)

Add this module to the fleet image's `xcaddy build` line in the Approximated
`fly/Dockerfile`, alongside the other Approximated-Inc modules — they're pulled
by `@commit` via go-get from GitHub (this repo is **public**, like its siblings
apx-caddy-stats / apx-caddy-trace), NOT by local path:

    RUN xcaddy build v2.11.3 \
      ... \
      --with github.com/Approximated-Inc/apx-caddy-stats@<commit> \
      --with github.com/Approximated-Inc/apx-caddy-challenge@<commit> \
      ...

- Build `--platform linux/amd64` for Fly.
- The image **tag** must contain `challenge` as a hyphen-delimited token (e.g.
  `...-coraza4.10-stats-challenge-v1`) so `ProxyServers.image_tag_has_module?`
  matches and Phoenix emits the challenge config. (The xcaddy `--with` compiles
  the module in; the tag token is what gates Phoenix config emission — both are
  required.)
- Pins: Go 1.26.1, Caddy v2.11.3 (kept in sync with apx-caddy-stats so xcaddy
  resolves one Caddy version).

## Deploy requirement

There is **no Fly secret**. The per-cluster secret is generated by Phoenix
config-gen (on first run when the image carries the `challenge` token) and
**stamped directly into the emitted `apps.apx_challenge.secret`**. It propagates
via the normal config-check pull (~1 min). Rotation is a config regen
(regenerate the cluster's `challenge_secret`), which invalidates outstanding
cookies (10-min TTL bounds the re-challenge wave). The config is fetched over
Approximated's authenticated internal-key channel, same as `apx_stats`'s
hash_salt.

## Scope (v1)

Enforces **ip / sni / path** challenge. **ja3/ja4 challenge is NOT served** —
TLS fingerprints are caddy-l4 connection vars that aren't surfaced to the HTTP
layer, so a fingerprint challenge fails **open** (traffic passes un-challenged).
To deny a fingerprint, use a `block` rule (enforced at L4). Enabling fingerprint
challenge later requires propagating `tls_ja3`/`tls_ja4` across the L4→L7 hop
(e.g. PROXY-protocol TLVs) — a separate slice.

## Test

    go test ./...

Go tests cover PoW solve/verify, cookie/token HMAC (incl. cross-protocol +
prefix binding), the pass-cookie policy (default cookies byte-identical to the
pre-policy format in both directions, renewal window and cap, prefix widths, UA
binding, config validation), the render-check fallback (each pass condition
and its failure, the pixel endpoint and what counts as a render, concurrent
replays, the stores, the non-rolling cookie, the opt-out, a golden test that
the opted-out page is byte-identical to the pre-fallback page, and a golden of
the default page), the handler (serve/verify/cookie-gate/non-browser/outcome
var), and page rendering. The real browser solve-and-redirect (incl. slow network +
budget mobile to validate difficulty-16 solve time) is verified on the canary,
not in CI.

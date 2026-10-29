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
(`issued | passed | passed_recently | failed`) for the apx-caddy-stats recorder
(Phase 9c).

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
machine (the shared bounded nonce LRU also used by Edge Verify). One solve
therefore mints one cookie, for the address and UA that fetched the page.
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
binding, config validation), the handler (serve/verify/cookie-gate/non-browser/outcome var),
and page rendering. The real browser solve-and-redirect (incl. slow network +
budget mobile to validate difficulty-16 solve time) is verified on the canary,
not in CI.

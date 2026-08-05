# Local end-to-end test for Edge Verify

Runs a minimal Caddy with the `apx-caddy-challenge` module so you can click through
the widget → PoW → token → edge-enforce flow in a real browser. No Fly, no TLS.

## 1. Build a Caddy binary with the local module

    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    # from the repo root:
    xcaddy build --with github.com/Approximated-Inc/apx-caddy-challenge=$(pwd)
    # produces ./caddy in the repo root

## 2. Run it against this config

    cd localtest
    ../caddy run --config caddy.json

## 3. Test in a browser — the happy path

Open **http://localhost:8899/** (must be `localhost` or `127.0.0.1`, NOT a LAN IP —
the widget's PoW uses `crypto.subtle`, which browsers only expose in a secure context;
`http://localhost` counts, `http://192.168.x.x` does not and the widget will fail open).

- DevTools → Network: you should see `POST /__apx_verify/challenge` then `POST /__apx_verify/token`.
- Inspect the `<form>`: a hidden `<input name="_apx_verify_token">` should have appeared.
- Submit the form → **"FORM ACCEPTED BY ORIGIN"** (token validated, passed through).

## 4. Test the block — a bot with no token

    curl -i -X POST http://localhost:8899/form -d 'email=x@y.z'
    # → HTTP/1.1 403 Forbidden   (enforce mode, no valid token)

    # An API-ish client gets JSON:
    curl -i -X POST http://localhost:8899/form \
      -H 'Sec-Fetch-Mode: cors' -H 'Sec-Fetch-Dest: empty' -H 'Accept: application/json' \
      -d 'email=x@y.z'
    # → 403 {"error":"edge_verify_failed"} (or similar)

## Knobs (edit caddy.json, restart)

- `verify_scoring`: `"off"` (default here — passes any submit, best for the token happy-path)
  → switch to `"lenient"` (or `"strict"`) to also exercise the probe checks (webdriver / missing-APIs).
  To see a reject, drive the widget from a headless browser (`navigator.webdriver === true` → `webdriver`),
  or hand-POST `/__apx_verify/token` with a `probes` payload whose `missing_apis` lists ≥3 entries
  (≥2 under `"strict"`) → `missing_apis` reject.
- `mode` on the `/form` route: `"enforce"` (blocks) vs `"monitor"` (always passes, just records the outcome —
  locally there's no analytics sink so you won't see counts; use enforce to see the gate work).
- `verify_difficulty`: 12 solves in well under a second; bump it to feel the PoW cost.

## What this does NOT cover

- Analytics (ClickHouse `edge_verify_attempts`) — needs apx-caddy-stats + CH; test those via the app's
  `:clickhouse` suite instead.
- The Phoenix dashboard tab / rules API / config generation — test those on the dev server (see the chat).

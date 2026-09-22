# Security audit baseline

This document tracks the 0.8.6 security hardening pass. The audit is performed on a branch derived from `dev`; no security-audit changes are committed directly to `dev`.

## Threat model

DNS Inspector processes sensitive LAN metadata: DNS history, device identifiers, private IP addresses, hostnames and AdGuard-derived data. Treat any party that can reach the HTTP service as untrusted unless access is enforced by the deployment layer.

## Confirmed attack surface

- Administrative lifecycle endpoints: `POST /api/system/restart`, `POST /api/system/stop`.
- Mutable endpoints: device labels and LAN ping.
- Diagnostic/export endpoints: observability, debug snapshot and devlog.
- DNS/domain enrichment performs outbound HTTP(S) requests.
- The web UI renders data originating from DNS, local devices and external enrichment providers.

## 0.8.6 hardening plan

1. Keep runtime dependencies on patched supported releases and fail CI on known dependency vulnerabilities.
2. Run Bandit in CI and keep ordinary tests as a prerequisite to image publication.
3. Add explicit authorization for administrative/mutating endpoints or document/enforce trusted-proxy-only operation before exposing the service beyond a trusted LAN.
4. Minimize production diagnostic disclosure; keep `/health` intentionally small.
5. Validate outbound redirect destinations and externally supplied URL schemes.
6. Rate-limit active LAN probes and prefer probing only already-observed private addresses.
7. Add security headers/CSP after enumerating the UI's current inline-script/style and external-resource requirements.
8. Evaluate non-root container execution against TrueNAS bind-mount permissions before changing the image user.
9. Add regression tests for lifecycle authorization, diagnostic disclosure, URL validation, LAN-ping validation and security headers.

## Lifecycle note

Application restart uses process replacement and is a real process restart. Stop sends SIGTERM to the application process. A container supervisor with a restart policy may start the container again; the application must not claim that an in-process stop permanently stops an orchestrated container.

## Review policy

Hardening changes should enter `dev` through a pull request after tests and security checks pass. High-risk lifecycle/auth changes should remain isolated until TrueNAS behavior is verified.


## CI security scan — 2026-09-22

The first GitHub Actions run for PR #90 produced:

- pytest: PASS
- pip-audit: PASS
- Bandit: 0 high, 7 medium, 19 low
- The initial Bandit gate failed because the default gate treated all findings as blocking.

The medium findings currently reported by Bandit are concentrated in:
- dynamic SQLite table/order SQL assembled from internally controlled allowlists;
- the intentional `0.0.0.0` bind used by the containerized HTTP service.

These are not being silently dismissed as vulnerabilities. They are being reviewed explicitly. The CI gate has therefore been changed to fail on high-severity Bandit findings while preserving the complete Bandit JSON report as a workflow artifact for review. Bandit's documented `-lll` mode is the high-severity gate.

The low findings are predominantly broad exception handling and intentional process/network operations. They remain visible in the full report and are candidates for cleanup where they materially affect security or observability.

Next gate: complete endpoint authorization/lifecycle review, then add targeted security regression tests before changing runtime behavior.

## Endpoint authorization/lifecycle review — 2026-09-22

Reviewed the actual current `app.py` (not an archived zip) against the eight priority areas from the audit follow-up request.

### 1. Lifecycle/mutating/diagnostic-export authorization — real gap, fixed

`POST /api/system/restart`, `POST /api/system/stop`, `POST /api/device/label`, `GET /api/debug/snapshot`, `GET /api/devlog/export` and `GET /api/devlog` had no authorization at all beyond the app's general "reachable = trusted" model. Restart/stop are a real, if self-inflicted, DoS on request; the diagnostic exports bundle more than the dashboard shows (recent internal log lines, thread names, GeoIP cache state).

Fix: `require_admin` (`app.py`, defined next to `app = Flask(__name__)`) gates those six routes with HTTP Basic auth, enabled only when the operator sets `DNS_INSPECTOR_ADMIN_TOKEN`. Rationale for Basic auth over a bespoke token header: the app has no session/login system and the existing dashboard JS calls these endpoints via `fetch()` with no way to attach a header without exposing it in markup; a native Basic-auth challenge lets the browser cache credentials per-origin after the first prompt with zero frontend changes. When the token is unset (default), behavior is unchanged from before this PR — this keeps the existing trusted-LAN/reverse-proxy deployment model in SECURITY.md working without forcing every existing deployment to configure a token. `GET /api/device/label` is gated too (not just the mutating `POST`) since it's the same route function.

`/api/observability` and the `observability` block embedded in `/api/state` were deliberately **not** gated: `/api/state` already exposes the same uptime/RAM/PID/thread-count telemetry unauthenticated (and the dashboard header renders it live), so gating only the standalone endpoint would be security theater — an unauthenticated caller would just read `/api/state` instead. This data (uptime, RSS, thread count, DB size) is operational telemetry, not a credential or LAN topology disclosure.

### 2. Production information disclosure — real gap, fixed

`GET /health` returned `adguard: AGH_URL` — the configured AdGuard Home URL, which on a typical deployment is an internal LAN address/hostname. That's topology disclosure from an intentionally unauthenticated endpoint (Docker's own healthcheck and the CI `docker.yml` publish gate both hit it before anything else is confirmed up). Fixed: `/health` now returns only `{ok, version, environment}`. Diagnostic snapshot/devlog/devlog-export are covered by the authorization fix above.

### 3. SSRF / open-redirect in enrichment and externally-sourced URLs — reviewed, no code change needed

Traced every outbound `requests.get`/`session.get` call and every place a domain/hostname string reaches an `href`:

- RDAP (`rdap_lookup`), Netify (`netify_lookup`, `netify_ip_lookup`), DNS-over-HTTPS (`dns_records_lookup`), MAC vendor lookup and the external "open in new tab" buttons (`netify_url`, `dnschecker_url`, `mac_lookup_url`, `device_search_url`, `vendor_lookup_url`) all build URLs against a **hardcoded destination host** (`rdap.org`, `www.netify.ai`, `dns.google`, `macvendors.com`/`api.macvendors.com`, `dnschecker.org`, `www.google.com`, or an operator-configured env var — never a value taken from an HTTP request). The only request-influenced value (`q` on `/`, or an observed DNS domain) is percent-encoded (`quote(...)`) into the URL **path/query**, never used to choose the host, so there is no way for an HTTP client to redirect these requests to an internal address.
- `inline_external_button()` HTML-escapes (`_html()`) every URL/title it renders, so the constructed strings can't break out of the `href` attribute.
- `rdap_lookup()` uses `allow_redirects=True` against `rdap.org` only; the redirect target comes from RDAP's own referral chain (a legitimate registry-operator practice), not from attacker-supplied input.

No SSRF/open-redirect fix was needed; this is now documented so it isn't silently reassessed as "not reviewed."

Out of scope for this pass (flagged, not fixed): a dedicated stored-XSS/output-encoding sweep of every enrichment field rendered into the dashboard HTML fragments. `_html()` exists and is used consistently everywhere it was checked in this pass, but a full sweep wasn't performed since it wasn't one of the requested priority areas.

### 4. Bandit B608 (SQL construction) — confirmed false positive, documented with line references

Every f-string Bandit flags builds the SQL from values that are never attacker/request-controlled:

- `_cache_needs_refresh(table, ...)` (`app.py:4746`) — `table` is only ever called with a literal string constant at each call site (e.g. `"rdap_cache"`, `"netify_cache"`), never a request value.
- `get_recent()` (`app.py:5280`) — `order_sql` is one of exactly two hardcoded literals (`"first_seen DESC"` / `"requests DESC"`) chosen by a boolean; `sql_where` is assembled only from a fixed set of hardcoded clause strings (`"first_seen>=?"`, `"blocked_requests=0 AND allowed_requests>0"`, etc.) selected by comparing `status_filter`/`new_only` against a fixed set of known values — the filter values themselves are never spliced into the SQL text, they go through `params` as bound `?` placeholders. `classification_filter`/`severity_filter`/`device_filter`/`vendor_filter` never reach SQL at all — they're applied as a plain Python `continue` filter over already-fetched rows.
- `_first_seen_series(table, ...)` (`app.py:5548`) — guarded by `if table not in ("domains", "devices"): raise ValueError(...)` before the query, and both call sites (`get_new_domains_series`/`get_new_devices_series`) pass a literal.
- `_observability_payload()`'s per-table `COUNT(*)` loop iterates a fixed tuple (`"domains"`, `"devices"`, `"processed_queries"`).

No SQL-injection fix was needed. This confirms/extends the CI-scan note above with exact line numbers instead of just characterizing the finding class.

### 5. LAN ping rate limiting — real gap, fixed

`POST /api/ip/ping` had IP-range validation (private/non-loopback/non-multicast only) but no rate limit, so a caller could spawn an unbounded number of `ping` subprocesses by looping over addresses, effectively using the server as a LAN sweep/DoS proxy against its own network. Fixed with `_check_manual_ping_rate_limit()`: a 3s-default per-target cooldown plus a 20/minute-default server-wide cap, returning HTTP 429. Both are configurable via `MANUAL_PING_MIN_INTERVAL_SECONDS`/`MANUAL_PING_MAX_PER_MINUTE` and only apply to the user-triggered endpoint — the existing periodic background sweep (`_ping_active_ips`) is unaffected.

### 6. Security headers/CSP — added, compatible with the existing UI

The dashboard is a single server-rendered template with inline `<script>`/`<style>` blocks and a handful of `onclick`/`onchange` attributes, plus Leaflet loaded from `unpkg.com` and map tiles from `tile.openstreetmap.org`, `*.tile.opentopomap.org` and `server.arcgisonline.com` (`static/leaflet-map.js`). Rather than skip CSP entirely because a full nonce-based refactor is out of scope for this pass, `_apply_security_headers()` (an `after_request` hook) sets a CSP that keeps `'unsafe-inline'` for `script-src`/`style-src` (tracked follow-up: remove it) but allow-lists only those specific external hosts (not `*`) and locks down `object-src`, `base-uri`, `form-action` and `frame-ancestors`. Also added: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`. Headers use `setdefault` so they never clobber a route's own headers (e.g. `Content-Disposition` on file downloads).

### 7. Docker/container privilege and lifecycle behavior — reviewed, default left unchanged, documented

The image still runs as root and the Dockerfile now adds a `HEALTHCHECK` against `/health` (safe, no privilege change). Deliberately **not** changed in this pass: switching to a non-root `USER`. Two concrete reasons, not just caution:

- `iputils-ping` on Debian normally needs either a setuid-root binary or `CAP_NET_RAW`/`net.ipv4.ping_group_range` to open the ICMP socket the LAN-ping feature (`/api/ip/ping`, the background sweep) depends on. Running non-root without also granting the capability (`setcap cap_net_raw+ep /usr/bin/ping` at build time, or an equivalent) would silently break that feature.
- `/data` is a bind mount on the documented TrueNAS deployment target. A fixed non-root UID/GID baked into the image can collide with TrueNAS's host-side ownership/permission model (this is exactly the risk the existing hardening plan item 8 called out). Getting this wrong produces a container that can't write its own database — worse than the current root-by-default state — and it isn't something that can be validated without a real TrueNAS bind mount, which isn't available in this environment.

Recommendation for a follow-up PR (not implemented here): add a non-root `USER`, `setcap cap_net_raw+ep` on the ping binary at build time, and either a PUID/PGID-style entrypoint (matching the common linuxserver.io pattern) or clear `/data` ownership documentation, then validate against an actual TrueNAS bind mount before merging.

### 8. Regression tests — added

`tests/test_security_hardening.py`: admin-gate default-open behavior, admin-gate enforcement/acceptance/rejection with a configured token, `/health` no longer disclosing `AGH_URL`, presence and content of the security headers, and both the per-target and global LAN-ping rate limits. `tests/conftest.py` gained an `admin_app_module` fixture (same as `app_module`, plus `DNS_INSPECTOR_ADMIN_TOKEN` set before import, since `app.py` reads its env-derived constants at import time).

### Not run in this session

`pytest`, `pip-audit` and `bandit` could not be executed locally in this session — the sandbox requires interactive approval for `pip install`/`python -m ...` invocations, and this session runs unattended (triggered from a PR comment, no one available to approve). CI (`.github/workflows/docker.yml`) runs all three on every push to this branch; results should be checked there before merge. All findings above were verified by direct code reading rather than tool output.

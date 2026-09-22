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

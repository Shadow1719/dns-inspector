# Security

## Scope

DNS Inspector is a self-hosted network-observation application. It handles potentially sensitive information including DNS domains, device identifiers, IP addresses and local network metadata.

## Deployment guidance

- Keep `/data` private and backed up appropriately.
- Do not publish `inspector.db`, `trackerdb.sqlite`, credentials or local network exports.
- Supply AdGuard credentials through environment variables or the secret mechanism provided by the deployment platform.
- Prefer exposing the UI only to trusted users or through an authenticated reverse proxy.
- Set `DNS_INSPECTOR_ADMIN_TOKEN` to enable browser admin authentication for the restart/stop, device-label and diagnostic-export/devlog endpoints. The UI exchanges the operator-entered token for a short-lived random HttpOnly/SameSite=Strict session cookie; the configured token is never embedded in HTML/JS, localStorage or sessionStorage. Unset by default so existing trusted-LAN/reverse-proxy deployments keep working unchanged.
- Do not expose AdGuard administrative credentials to client-side JavaScript.

## Reporting a vulnerability

Please avoid publishing credentials, private DNS data or a working exploit in a public issue.

For sensitive reports, contact the repository owner through GitHub before public disclosure.

For ordinary bugs, use the repository issue tracker.

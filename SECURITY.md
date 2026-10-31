# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private
vulnerability reporting ("Report a vulnerability" on the Security tab) and
include steps to reproduce, the affected version and the impact you expect.

We aim to acknowledge reports within a week and will keep you updated while a
fix is prepared. Reporters are credited in the release notes unless they ask
not to be.

## Supported versions

Only the latest release receives security fixes while the project is in 0.x.

## Threat model

STRX EYE processes data from untrusted sources (DNS answers, RDAP JSON, web
pages, certificate logs) and may be pointed at hostile infrastructure. The
main protections, and where they live:

| Risk | Mitigation | Code |
|---|---|---|
| Investigation data steering requests into the analyst's network (SSRF) | Direct collectors resolve the host first and refuse private, loopback, link-local, CGNAT and multicast addresses, on every redirect hop. The TLS collector connects to the vetted address to avoid DNS rebinding. | `net.ensure_public_host`, `collectors/website.py` |
| Script injection through collected values | The UI renders values as text only. HTML reports are autoescaped and carry a CSP that blocks scripts; the in-app preview is a sandboxed iframe without script permission. | `reporting/`, `ReportPanel.tsx` |
| Spreadsheet formula injection | CSV values starting with `= + - @` are prefixed with `'`. | `reporting._csv_safe` |
| Other local processes or web pages calling the API | Loopback-only bind, per-launch random token (constant-time comparison), Host header allow-list against DNS rebinding, `SameSite=Strict` HttpOnly cookie. | `server.py` |
| Path traversal when serving the UI | Files are served only if the resolved path is inside the UI folder. | `server.py` |
| Untrusted plugins | Installed plugins are not imported until trusted by name and exact version; upgrades must be trusted again. | `plugins.py` |
| API keys leaking into files, logs or shell history | Keys live in the OS keychain (or an environment variable), are read through a hidden prompt, are write-only in the UI and API, and are never written to config, database, evidence or audit log. | `secrets.py` |
| Tampered update downloads | The updater only downloads from `github.com/<repo>/releases/download/` and runs the installer only if its SHA-256 matches `SHA256SUMS.txt` from the same release. | `updater.py` |
| Collecting more personal data than needed | RDAP personal contact fields and cookie values are never stored. | `collectors/rdap.py`, `collectors/website.py` |

Known gaps:

- `ensure_public_host` and the HTTP request in the `http` collector resolve the
  name separately, leaving a small DNS-rebinding window for that collector.
- Plugins, once trusted, run with the user's full permissions. There is no
  sandbox.
- The local database is not encrypted at rest; use full-disk encryption.
- Releases are not code-signed. The update checksum protects against
  corrupted or altered downloads, not against a compromised GitHub account;
  signed releases are needed for that.

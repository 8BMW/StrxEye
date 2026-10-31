# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-10-31

First public release.

### Added

- Windows desktop app (native window via WebView2) with an Inno Setup
  installer and a portable zip; Linux and macOS builds. Each build is
  smoke-tested in CI with `--self-test`.
- In-app update check against GitHub Releases, with download and silent
  install on Windows. The installer only runs if its SHA-256 matches the
  release's `SHA256SUMS.txt`. The check can be turned off.
- Release workflow that builds all platforms, writes checksums and publishes
  the GitHub release from a version tag.
- New collectors: `certspotter` (CT), `passive_dns` (mnemonic), `internetdb`
  (Shodan), `threatfeeds` (Spamhaus DROP, Feodo Tracker, Tor exits, matched
  locally), `otx` (AlienVault OTX), `virustotal` (requires a key) and `gleif`
  (company registry).
- New target types: file hashes and organisations (`org:Name`), and a
  `malware` entity type.
- API keys stored in the OS keychain (`strxeye keys`, Settings → API keys).
  Collectors whose key is missing are skipped.
- Full-text search across all investigations, including raw evidence
  (`strxeye search`, Search page).
- Graph analytics: shortest path, clusters, most-connected entities
  (`strxeye graph path|analyze`, graph panel).
- Timeline of dated events (`strxeye investigate timeline`, Timeline tab).
- STIX 2.1 export with deterministic SCO identifiers; inferred links are
  excluded.
- Domain expansion now also checks resolved IPs against threat lists and
  InternetDB.

### Changed

- Database schema version 2 (adds the search index). Existing databases are
  migrated automatically on first open.

## [0.1.0] - 2026-10-31

First development version.

### Added

- Collectors: `dns`, `rdap` (domain, IP, ASN), `crtsh`, `reverse_dns`, `asn`
  (Team Cymru), `wayback`, and direct `http` and `tls` collectors that only run
  when explicitly allowed.
- Engine with per-collector timeouts, cancellation, bounded concurrency,
  retries with backoff, per-host rate limits and optional one-hop IP expansion.
- SQLite storage with schema migrations, append-only runs, raw evidence keyed
  by SHA-256, audit log and secure deletion.
- Graph builder with per-edge provenance and a correlation step for shared IPs,
  shared served certificates and likely hosting providers, each with an
  explanation.
- Run-to-run comparison that skips collectors which failed in either run.
- HTML, JSON and CSV reports.
- `strxeye` CLI with JSON output and documented exit codes.
- Local API (`strxeye serve`) and a React UI: overview, collection with live
  progress and cancel, entity explorer, graph, evidence library, history,
  reports, collectors, audit log, settings, command palette, dark and light
  themes.
- Plugin discovery through entry points; plugins run only after being trusted
  by name and version.

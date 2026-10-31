# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - unreleased

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

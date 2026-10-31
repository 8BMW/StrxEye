# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-10-31

First public release.

### Desktop app and distribution

- Windows desktop app (native window via WebView2) with an Inno Setup
  installer and a portable zip; Linux and macOS builds. Each build is
  smoke-tested in CI with `--self-test`.
- In-app update check against GitHub Releases, with download and silent
  install on Windows. The installer only runs if its SHA-256 matches the
  release's `SHA256SUMS.txt`. The check can be turned off.
- Release workflow that builds all platforms, writes checksums and publishes
  the GitHub release from a version tag.

### Sources

- 26 collectors covering 44 external sources. Beyond DNS, RDAP, crt.sh, ASN
  and the Wayback Machine: `certspotter`, `passive_dns` (mnemonic),
  `internetdb` (Shodan), `mailsec` (MTA-STS, TLS-RPT, BIMI, DKIM),
  `hackertarget`, `urlscan`, `ripestat` (routing, RPKI, abuse contact,
  geolocation estimate), `peeringdb`, `robtex`, `greynoise`, `dnsbl` (6 DNS
  block lists), `otx`, `gleif`, `malpedia`, and with a key `virustotal`,
  `abusech` (ThreatFox, URLhaus, MalwareBazaar) and `abuseipdb`.
- `threatfeeds` matches 13 lists locally: Spamhaus DROP, Feodo Tracker, Tor
  exits, FireHOL Level 1, ET compromised, Binary Defense, IPsum, CINS Army,
  blocklist.de, GreenSnow, DShield, Phishing Army and OpenPhish.
- Guessed CVEs are checked against CISA KEV and scored with EPSS; the `tls`
  collector checks the served certificate against abuse.ch SSLBL; the `http`
  collector extracts analytics and ad account IDs.
- Target types for file hashes, organisations (`org:Name`) and malware
  families (`malware:Name`).
- API keys stored in the OS keychain (`strxeye keys`, Settings → API keys).
  Collectors whose key is missing are skipped.

### Analysis

- Threats tab and `strxeye investigate threats`: block-list hits, OTX
  mentions, VirusTotal detections and exposure signals in one list, with
  fixed, documented severity rules per source.
- Malware intelligence: threat-actor entities with `attributed_to` links,
  automatic Malpedia expansion for any family a run finds, a Malware tab and
  `strxeye investigate malware`.
- Correlation that separates strong signals (tracking IDs, self-hosted
  nameservers, registrant organisation) from weak ones. Shared IPs on CDNs,
  clouds and shared hosting, multi-tenant certificates, DNS providers and
  privacy registrants are suppressed, and the graph lists what was not linked
  and why. Independent signals combine as 1 − ∏(1 − w).
- Monitoring: watches re-collect targets on a schedule and turn changes into
  alerts, compared per (collector, target) pair. Alerts page with an unread
  badge, and `strxeye monitor add|list|pause|remove|run` and `strxeye alerts`.
- Full-text search across all investigations, including raw evidence.
- Graph analytics (shortest path, clusters, most-connected entities) and a
  timeline of dated events.
- STIX 2.1 export with deterministic SCO identifiers; inferred links are
  excluded.
- Plugins: `strxeye plugins new` scaffolds a working plugin with a test; a
  Plugins page lists installed plugins and trusts an exact version after
  explicit confirmation.

### Changed

- Database schema version 4. Databases from 0.1.0 migrate automatically on
  first open.

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

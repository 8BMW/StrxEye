<p align="center"><img src="docs/assets/logo.png" alt="STRX EYE" width="300"></p>

<p align="center">
  <a href="https://github.com/8BMW/StrxEye/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/8BMW/StrxEye?label=release"></a>
  <a href="https://github.com/8BMW/StrxEye/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/8BMW/StrxEye/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.12+" src="https://img.shields.io/badge/python-3.12%2B-blue">
  <img alt="Platforms" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey">
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-green"></a>
</p>

# STRX EYE

STRX EYE is a local-first OSINT and threat-intelligence workbench for domains,
IP addresses, AS numbers, file hashes and companies. It pulls from public
sources: DNS, RDAP registries, Certificate Transparency, passive DNS, BGP, Shodan
InternetDB, block lists, AlienVault OTX, VirusTotal, the GLEIF company register
and the Internet Archive. Every fact keeps its source, UTC timestamp, confidence
and the raw response it was parsed from. Results come together as a graph, a
timeline, a threat summary and full-text search, and export to HTML, JSON, CSV
or STIX 2.1.

It runs as a Windows desktop app with an installer and auto-update, as portable
builds for Linux and macOS, and as a Python package with the `strxeye`
command-line tool. All of them share one engine and one local database.

<p align="center">
  <img src="docs/media/demo.gif" alt="Creating an investigation, collecting on an IP address, reviewing its threat signals, graph, timeline and report" width="900">
  <br>
  <sub>30-second walkthrough recorded from the app: a new case, live collection on an IP from an alert, the botnet C2 hit in Threats, the graph and the report. <a href="docs/media/demo.mp4">MP4 version</a>.</sub>
</p>

## Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Sources](#sources)
- [Command line](#command-line)
- [Limitations](#limitations)
- [Development](#development)

## Features

**Collection**
- 15 collectors across DNS, registration data, certificates, passive DNS, BGP,
  open ports, block lists, threat reports, reputation, company registries and
  web archives. The full list is under [Sources](#sources).
- Passive by default. Nothing contacts the target unless you allow direct
  collection for a run. There is no port scanning.
- Domain expansion: also look up owners, ASNs, block-list status and open ports
  for every IP a domain resolves to.
- Concurrent collectors with per-collector timeouts, retries, rate limits and
  cancellation. A failed source is reported as failed, never silently skipped.

**Evidence you can check**
- Every observation records its collector, method, UTC time and confidence, and
  links to the stored raw response (DNS answer, RDAP JSON, CT entry), which is
  identified by its SHA-256.
- Relationships seen by a source are kept apart from links STRX EYE suggests
  itself (shared IP, shared certificate, likely hosting provider). Suggested links
  are drawn dashed, carry low confidence and come with a written reason.

**Analysis**
- Interactive graph with type filters, folding, clusters, shortest path between
  any two entities, provenance on every edge, and PNG/SVG/JSON export.
- Threats view: block-list hits, OTX mentions, VirusTotal detections and exposure
  signals in one place. Severity follows fixed, documented rules; there is no
  opaque risk score.
- Timeline of registrations, certificate validity, passive DNS sightings, archive
  captures and threat reports.
- Full-text search across every investigation, including raw evidence.
- Run history with diffs. A source that failed in either run is left out of the
  comparison, so an outage does not look like a change.

**Reporting and exchange**
- HTML report (printable to PDF), JSON, CSV, and a STIX 2.1 bundle for OpenCTI,
  MISP or a TAXII server.
- Reports keep observations, inferred links and rule-based findings in separate,
  labelled sections.

**Privacy and security**
- Everything is stored in one local SQLite file. No account, no telemetry.
- Optional API keys live in the OS keychain, never in files.
- The local engine listens on loopback only and requires a per-launch token.
  Direct collectors refuse private and internal addresses (SSRF protection).
  See [SECURITY.md](SECURITY.md).

## Screenshots

All screenshots come from the running app on data collected from the live sources
listed below, at version 1.0.1. The demo cases are python.org's public
infrastructure, two botnet C2 servers currently listed by abuse.ch with a Tor
exit for comparison, and Cloudflare as a supplier.

**Windows desktop app**: the packaged `STRX EYE.exe`, a native window running the bundled engine.

<img src="docs/media/desktop-window.png" alt="STRX EYE desktop window on Windows showing the overview of four investigations" width="900">

**Graph**: python.org's hosting, coloured by cluster, with the shortest path from the domain to its CDN's AS highlighted. The panel on the right shows the selected AS and every observation behind it.

<img src="docs/media/graph.png" alt="Investigation graph with clusters and a highlighted shortest path" width="900">

**Threats**: two IPs from an alert queue are on the abuse.ch Feodo Tracker (Emotet and QakBot C2). Banner-based CVE guesses are grouped and marked as unverified.

<img src="docs/media/threats.png" alt="Threats view with high-severity block-list hits" width="900">

**Entity detail and evidence**: each value shows which source reported it and when, with a link to the stored raw response.

<table>
  <tr>
    <td><img src="docs/media/entities.png" alt="Entity list and detail panel"></td>
    <td><img src="docs/media/evidence.png" alt="Raw evidence viewer with SHA-256"></td>
  </tr>
  <tr>
    <td><img src="docs/media/threat-entity.png" alt="Detail of a botnet C2 IP with BGP and OTX observations"></td>
    <td><img src="docs/media/timeline.png" alt="Timeline from 1995 registration to current passive DNS"></td>
  </tr>
  <tr>
    <td><img src="docs/media/search.png" alt="Search across investigations"></td>
    <td><img src="docs/media/collect.png" alt="Collection run with per-collector status"></td>
  </tr>
  <tr>
    <td><img src="docs/media/report.png" alt="HTML report preview"></td>
    <td><img src="docs/media/overview.png" alt="Overview of investigations"></td>
  </tr>
  <tr>
    <td><img src="docs/media/graph-light.png" alt="Graph in the light theme"></td>
    <td><img src="docs/media/settings-light.png" alt="Settings in the light theme"></td>
  </tr>
</table>

## Installation

**Windows 10/11:** download `STRX-EYE-Setup-<version>.exe` from
[Releases](https://github.com/8BMW/StrxEye/releases/latest) and run it. It
installs for your user account, so no administrator rights are needed, and can add
the `strxeye` command to your PATH. A portable zip is published alongside it.
The installer is not code-signed yet, so SmartScreen may show "Windows protected
your PC". If the checksum matches (see below), choose *More info → Run anyway*.

**Linux / macOS:** download the `.tar.gz` for your platform from
[Releases](https://github.com/8BMW/StrxEye/releases/latest), extract it, and run
`STRX EYE/STRX EYE` for the desktop app or `STRX EYE/strxeye` for the CLI. On
Linux the app opens its interface in your default browser. On macOS, allow it
under *System Settings → Privacy & Security* the first time.

**Python (any OS, 3.12+):**

```bash
pip install "strxeye[desktop] @ https://github.com/8BMW/StrxEye/releases/download/v1.0.1/strxeye-1.0.1-py3-none-any.whl"
strxeye-desktop
```

**Updates:** the Windows app checks GitHub Releases when it starts. You can
download and install a new version from *Settings → Updates*. The installer only
runs if its SHA-256 matches the checksum file published with the release. You can
turn the check off in Settings. Python installs update with `pip install -U`.

**Verifying downloads:** each release includes `SHA256SUMS.txt`.

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

```powershell
Get-FileHash .\STRX-EYE-Setup-1.0.1.exe -Algorithm SHA256
```

## Quick start

1. Open STRX EYE and choose **New investigation**. Give it a name and note the
   scope you are authorised for.
2. In **Collect**, enter a target: `example.com`, `8.8.8.8`, `AS13335`, a file
   hash, or `org:Company Name`. Applicable collectors are pre-selected. Keep
   *Expand discovered IPs* on for domains.
3. Watch each collector finish. Failures show the reason, such as "crt.sh returned
   HTTP 502".
4. Review **Threats** first, then **Graph** and **Timeline**. Click any value to
   see where it came from, and *evidence* to see the raw response.
5. Export from **Report**: HTML for people, STIX for platforms.

API keys are optional. VirusTotal needs one. With an OTX key, OTX allows more
requests. Add keys under *Settings → API keys* or with `strxeye keys set virustotal`.

## Sources

| Collector | Accepts | Collects | Contacts | Key |
|---|---|---|---|---|
| `dns` | domain | A, AAAA, CNAME, MX, NS, TXT/SPF, SOA, CAA, DMARC | your resolver | – |
| `rdap` | domain, IP, ASN | registrar, dates, status, DNSSEC; network owner; AS holder | IANA + registry/RIR | – |
| `crtsh` | domain | certificates and subdomains from CT logs | crt.sh | – |
| `certspotter` | domain | unexpired certificates and subdomains | api.certspotter.com | – |
| `passive_dns` | domain, IP | historical resolutions with first/last seen | api.mnemonic.no | – |
| `reverse_dns` | IP | PTR records | your resolver | – |
| `asn` | IP, ASN | announcing AS, BGP prefix, AS name | Team Cymru (DNS) | – |
| `internetdb` | IP | open ports, hostnames, software, CVE guesses | internetdb.shodan.io | – |
| `threatfeeds` | IP | Spamhaus DROP, Feodo Tracker, Tor exit list | list downloads only | – |
| `otx` | domain, IP, hash | community threat reports, malware families | otx.alienvault.com | optional |
| `virustotal` | domain, IP, hash | engine verdicts, reputation, threat label | virustotal.com | required |
| `gleif` | organisation | legal entities, jurisdiction, status, parent | api.gleif.org | – |
| `wayback` | domain, URL | first/latest capture, one per year | web.archive.org | – |
| `http` *(direct)* | domain, URL | status, redirects, security headers, cookie flags, technologies, robots.txt | the target | – |
| `tls` *(direct)* | domain, URL | served certificate, protocol, validation | the target | – |

Block lists are downloaded whole and matched locally, so the IPs you check are
never sent to the list operators.

**Out of scope:** STRX EYE does not search for private individuals. There is no
people search, no phone-number lookup, no personal emails and no social-media
profiling. That data mostly comes from breaches and data brokers, and making it
searchable enables stalking. Company research uses the official GLEIF register and
keeps organisation-level fields only. Personal RDAP contact data and HTTP cookie
values are never stored.

## Command line

```bash
strxeye domain example.com --expand        # look up a domain and its IPs
strxeye ip 1.1.1.1
strxeye hash 44d88612fea8a8f36de82e1278abb02f
strxeye org "Cloudflare"

strxeye investigate create "Alert 4512" -d "Outbound beacon from host WS-114"
strxeye investigate run 3fa2 185.220.101.4  # IDs can be shortened
strxeye investigate threats 3fa2
strxeye investigate timeline 3fa2
strxeye graph path 3fa2 example.com AS13335
strxeye search 185.220.101                  # across all investigations
strxeye report 3fa2 --format stix -o case.stix.json
```

Every data command accepts `--json`. Exit codes: `0` success (including "nothing
found"), `1` some collectors failed, `2` invalid input, `3` all collectors failed,
`4` not found. Run `strxeye --help` for the full command list.

## Where data is stored

| | Windows | Linux | macOS |
|---|---|---|---|
| Config | `%LOCALAPPDATA%\strxeye\config.toml` | `~/.config/strxeye/` | `~/Library/Application Support/strxeye/` |
| Database, feed cache, logs | `%LOCALAPPDATA%\strxeye\` | `~/.local/share/strxeye/` | `~/Library/Application Support/strxeye/` |

Set `STRXEYE_HOME` to keep a workspace in its own folder, for example one per
engagement. Deleting an investigation erases it with SQLite `secure_delete` and
compacts the file. Copies kept by backups or sync tools are outside the
application's reach.

## Limitations

- **Missing data is not evidence of absence.** Sources have gaps, delays and rate
  limits. STRX EYE reports each failure rather than hiding it.
- **crt.sh is often overloaded** and returns HTTP 502. Cert Spotter covers
  unexpired certificates in the meantime; re-run later for the full history.
- **Passive DNS** (mnemonic) has partial coverage and is capped at 200 records
  per query.
- **InternetDB** can be weeks old. Its CVEs are guesses based on software
  versions, so they are shown as unverified with low confidence.
- **OTX pulses** are community submissions. A mention is a lead, not proof. When
  OTX allow-lists an indicator (for example a popular domain), its pulses are
  counted but not imported.
- **VirusTotal** free keys allow 4 requests a minute; the collector waits.
- **GLEIF** searches by name, so results are candidates until you confirm them.
- **Clusters and paths** describe the collected graph, not the real world. Shared
  hosting is not shared ownership.
- **Not code-signed yet:** SmartScreen and Gatekeeper warn on first launch.
- **Not included yet:** scheduled re-collection with alerts, pushing to TAXII
  servers, multi-user collaboration, direct PDF export (print the HTML report
  instead), and the AI assistant planned for a later release.

## Development

```bash
pip install -e ".[dev,desktop]"
pytest                 # unit tests, no network
pytest -m live         # checks against the real public sources
ruff check src tests

cd apps/desktop
npm ci && npm test && npm run typecheck
npm run bundle         # build the UI into the Python package
```

[docs/releasing.md](docs/releasing.md) covers building the installer and
publishing a release. See also [docs/architecture.md](docs/architecture.md),
[docs/plugins.md](docs/plugins.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible use

STRX EYE is for security research, incident response, journalism and authorised
assessments. Only use direct collection against systems you are authorised to
contact, and follow each source's terms of use.

## License

MIT. See [LICENSE](LICENSE).

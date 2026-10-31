<p align="center"><img src="docs/assets/logo.png" alt="STRX EYE" width="320"></p>

# STRX EYE

STRX EYE is a local-first OSINT and threat-intelligence investigation tool for
domains, IP addresses, AS numbers, file hashes and companies. It collects from
public sources (DNS, RDAP registries, Certificate Transparency, passive DNS,
BGP data, Shodan InternetDB, threat block lists, AlienVault OTX, VirusTotal,
the GLEIF company registry, the Internet Archive). Every fact keeps its source,
timestamp, confidence and the raw response it came from. You can explore the
results as a graph, a timeline and full-text search, compare runs over time,
and export them as reports or STIX 2.1.

It ships as a Windows desktop app with an installer, as portable builds for
Linux and macOS, and as a Python package with the `strxeye` command-line tool.
Every one of them uses the same engine and the same local database.

## Install

**Windows:** download `STRX-EYE-Setup-<version>.exe` from
[Releases](https://github.com/8BMW/StrxEye/releases) and run it. It installs
for your user account (no administrator rights needed) and can optionally add
the `strxeye` command to your PATH. The installer is not code-signed yet, so
SmartScreen may show "Windows protected your PC"; choose *More info* and then
*Run anyway* if the checksum matches (see [Verifying downloads](#verifying-downloads)).
A portable zip is published alongside it.

**Linux / macOS:** download the `.tar.gz` for your platform, extract it, and run
`STRX EYE/STRX EYE` (desktop) or `STRX EYE/strxeye` (CLI). On Linux the desktop
build opens the UI in your default browser.

**Python (any OS):** Python 3.12+.

```bash
pip install "strxeye[desktop] @ https://github.com/8BMW/StrxEye/releases/download/v1.0.0/strxeye-1.0.0-py3-none-any.whl"
strxeye-desktop        # desktop window
strxeye --help         # command line
```

**Updates:** the Windows app checks GitHub Releases at start-up and can
download and install a new version from *Settings → Updates*. The installer is
only run if its SHA-256 matches the checksum file published with the release.
You can turn the check off in Settings. Python installs update with
`pip install -U`.

### Verifying downloads

Every release includes `SHA256SUMS.txt`.

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

```powershell
Get-FileHash .\STRX-EYE-Setup-1.0.0.exe -Algorithm SHA256
```

## What it does

- **Passive by default.** A fresh install only queries third-party services.
  Nothing contacts the target's own servers unless you allow direct collection
  for a run or turn it on in settings. Port scanning is not included.
- **Evidence for every observation.** Each fact records the collector, method,
  UTC time and confidence, plus the SHA-256 of the stored raw response.
- **Observed vs inferred.** STRX EYE suggests some links itself: shared IP,
  shared certificate, likely hosting provider. These are shown separately from
  what sources reported, with low confidence and a written explanation. Shared
  infrastructure is never presented as common ownership.
- **Threat intelligence.** Spamhaus DROP, abuse.ch Feodo Tracker (botnet C2)
  and the Tor exit list are downloaded and matched locally, so your IPs are not
  sent to the list operators. OTX community reports and VirusTotal verdicts
  are kept as raw counts with explanations, not turned into a black-box score.
- **Analysis.** Shortest path between any two entities. Clusters of related
  infrastructure. Most-connected entities. A timeline of registrations,
  certificates, passive DNS sightings, archive captures and threat reports.
  Full-text search across all investigations, including raw evidence.
- **Run history.** Re-running a target adds a run instead of overwriting.
  Diffs skip collectors that failed in either run, so an outage does not look
  like a change.
- **Reports** in HTML, JSON, CSV and **STIX 2.1** (for OpenCTI, MISP and TAXII
  servers). Reports separate observations, inferences and rule-based
  interpretations.
- **Private by default.** One local SQLite file. No telemetry, no accounts. API
  keys (optional) live in the OS keychain.

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
| `internetdb` | IP | open ports, hostnames, software, banner-based CVE guesses | internetdb.shodan.io | – |
| `threatfeeds` | IP | Spamhaus DROP, Feodo Tracker, Tor exit list | list downloads only | – |
| `otx` | domain, IP, hash | community threat reports, malware families | otx.alienvault.com | optional |
| `virustotal` | domain, IP, hash | engine verdicts, reputation, threat label | virustotal.com | required |
| `gleif` | organisation | legal entities, jurisdiction, status, parent company | api.gleif.org | – |
| `wayback` | domain, URL | first/latest capture, one per year | web.archive.org | – |
| `http` *(direct)* | domain, URL | status, redirects, security headers, cookie flags, technologies, robots.txt | the target | – |
| `tls` *(direct)* | domain, URL | served certificate, protocol, validation | the target | – |

Keys: `strxeye keys set virustotal` (or *Settings → API keys* in the app). The
key is read from a hidden prompt and stored in Windows Credential Manager,
macOS Keychain or Secret Service; `STRXEYE_KEY_<NAME>` environment variables
also work. Collectors that need a missing key are skipped, not failed.

### What STRX EYE does not do

It does not search for private individuals: no people search, no phone
numbers, no personal emails, no social-media profiling. That data mostly
comes from breaches or data brokers, and making it searchable enables
stalking and harassment. Organisation research uses the official GLEIF legal
entity register, and only stores organisation-level fields: city and country,
not street addresses. RDAP personal contact data and HTTP cookie values are
never stored.

## Command line

```bash
strxeye domain example.com --expand            # also look up owners, ASNs, threat lists for its IPs
strxeye domain example.com --direct            # also fetch headers and the TLS cert from the site
strxeye ip 1.1.1.1
strxeye asn AS13335
strxeye hash 44d88612fea8a8f36de82e1278abb02f
strxeye org "Cloudflare"
strxeye lookup https://example.com/            # detects the type; prefix companies with org:

strxeye investigate create "Phishing kit infrastructure" -d "Ticket 4512"
strxeye investigate run 3fa2 example.com --expand
strxeye investigate show 3fa2
strxeye investigate entities 3fa2 --type ip
strxeye investigate timeline 3fa2
strxeye investigate diff 3fa2 <older-run> <newer-run>
strxeye graph path 3fa2 example.com AS13335
strxeye graph analyze 3fa2
strxeye search 185.220.101                     # across all investigations, including raw evidence
strxeye report 3fa2 --format stix -o case.stix.json
strxeye keys list
strxeye update
```

Every data command accepts `--json`. Exit codes: `0` success (including
"nothing found"), `1` some collectors failed, `2` invalid input, `3` all
collectors failed, `4` not found, `130` interrupted.

`strxeye serve` runs the engine with the web UI on 127.0.0.1 and prints a
one-time login link, for using the UI from a browser without the desktop
wrapper.

## Desktop app

Overview, global **Search**, **Collect** (live progress, cancel, direct and
expansion options, collectors that need keys are marked), **Entities**
(searchable, with provenance and raw evidence per observation), **Graph**
(filters, inferred-link toggle, cluster colouring, shortest path, folding,
PNG/SVG/JSON export), **Timeline**, **Evidence**, **History** (run diff),
**Report** (HTML preview; HTML/JSON/CSV/STIX download), Collectors, Audit log,
Settings (theme, collection limits, API keys, updates).

Keyboard: `Ctrl+K` command palette, `Ctrl+Shift+F` search, `Ctrl+Alt+N` new
investigation, `Alt+1`…`Alt+7` workspace tabs, `/` focus entity search.

## Where data is stored

| | Windows | Linux | macOS |
|---|---|---|---|
| Config | `%LOCALAPPDATA%\strxeye\config.toml` | `~/.config/strxeye/` | `~/Library/Application Support/strxeye/` |
| Database, feed cache, logs | `%LOCALAPPDATA%\strxeye\` | `~/.local/share/strxeye/` | `~/Library/Application Support/strxeye/` |

`STRXEYE_HOME=/some/folder` keeps everything in one folder (one per
engagement, for example). Deleting an investigation removes it with SQLite
`secure_delete` and compacts the file; copies kept by backups, sync tools or
SSD wear levelling are beyond the application's reach.

## Limitations

- Missing data is not proof that something does not exist. Sources have gaps,
  delays and rate limits, and failures are reported per collector rather than
  hidden.
- crt.sh is often overloaded; Cert Spotter covers unexpired certificates when
  it is down. Mnemonic passive DNS has partial coverage and returns at most 200
  records per query here.
- InternetDB data can be weeks old, and its CVEs are guesses from software
  versions (confidence 0.4).
- OTX pulses are community submissions, so appearing in one is a lead, not
  proof. Popular domains appear in many pulses. OTX's allow-list flag is shown
  when present.
- VirusTotal free keys allow 4 requests a minute; the collector waits.
- GLEIF name search returns candidates; the link to your search term has
  confidence 0.5 until you confirm it.
- Clusters and shortest paths describe the collected graph, not the real world.
- Not yet included: code-signed installers, scheduled re-collection with
  alerts, TAXII server push, multi-user collaboration, the AI assistant (planned
  for a later release), direct PDF (print the HTML report instead).

## Development

```bash
pip install -e ".[dev,desktop]"
pytest                 # unit tests, no network
pytest -m live         # checks against real public services
ruff check src tests

cd apps/desktop && npm ci && npm test && npm run typecheck
npm run bundle         # builds the UI into the Python package
```

Building the desktop app and installer is described in
[docs/releasing.md](docs/releasing.md). See also
[docs/architecture.md](docs/architecture.md), [docs/plugins.md](docs/plugins.md)
and [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible use

STRX EYE is for security research, incident response, journalism and
authorised assessments. Only use direct collection against systems you are
authorised to contact, and respect each source's terms of use.

## License

MIT. See [LICENSE](LICENSE).

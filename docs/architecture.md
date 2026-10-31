# Architecture

```
            strxeye CLI ─┐
                         ├─> Engine ──> Collectors ──> public sources
 React UI ─> local API ──┘     │
 (strxeye serve)               └─> Store (SQLite) <── graph / correlation / history / reports
```

The CLI and the UI never talk to sources or the database on their own. Both go
through `Engine` and `Store`, so a result looks the same whichever interface
produced it.

## Layout

| Path | Responsibility |
|---|---|
| `src/strxeye/models.py` | Entity, Observation, Relationship, Evidence, CollectorResult |
| `src/strxeye/targets.py` | Parsing and normalising user input (IDNA, IP, ASN, URL, hash) |
| `src/strxeye/net.py` | HTTP client, retries, rate limiting, SSRF guard |
| `src/strxeye/collectors/` | One module per source; `base.py` defines the interface |
| `src/strxeye/engine.py` | Selecting and running collectors, timeouts, cancellation, expansion |
| `src/strxeye/storage/` | SQLite schema, migrations and queries |
| `src/strxeye/graph.py` | Nodes and merged edges with provenance |
| `src/strxeye/correlation.py` | Inferred relationships with explanations |
| `src/strxeye/history.py` | Run-to-run comparison |
| `src/strxeye/reporting/` | HTML/JSON/CSV reports and rule-based interpretations |
| `src/strxeye/plugins.py` | Entry-point discovery and trust |
| `src/strxeye/cli/` | Typer commands and Rich output |
| `src/strxeye/server.py` | FastAPI app for the UI |
| `apps/desktop/` | React + TypeScript + Tailwind + Cytoscape UI |

A single Python package (rather than one package per area) is deliberate: it
installs as one wheel with one version, and the module boundaries above are
enough to keep responsibilities apart at the current size.

## Data model

- An **entity** is unique per investigation by `(type, value)`. Values are
  normalised before storage (lowercase ASCII domains, canonical IPs, `AS123`).
- An **observation** is one fact about one entity from one collector in one
  run. Observations are never updated; a later run adds new rows.
- A **relationship** is a directed edge with origin collector, confidence and
  evidence. The graph merges repeated observations of the same edge and keeps
  the list as provenance.
- **Evidence** is the raw response text, keyed by its SHA-256 within an
  investigation, so identical responses are stored once.
- **Inferred** relationships are computed when the graph is built and never
  written to the database, so improving the rules changes old investigations
  too and nothing inferred can be mistaken for a stored observation.

## Collection lifecycle

1. The target is parsed and normalised (`targets.parse_target`).
2. `Engine.select` picks collectors that accept the type; direct collectors
   are dropped unless allowed.
3. A run row is created and the target added as a seed.
4. Collectors run concurrently (max 6) with a per-collector timeout. Each
   result is saved as soon as it arrives, so cancelling keeps finished work.
5. With expansion on, IP collectors run on addresses discovered in step 4
   (capped by `collection.max_expansions`).
6. The run is marked `completed`, `cancelled` or `failed`. Runs still marked
   `running` when the server starts are set to `interrupted`.

Collector outcomes are one of `ok`, `no_data`, `partial`, `error`, `timeout`,
`cancelled`. "Nothing found" is `no_data`, not an error.

## Local API

`strxeye serve` binds to 127.0.0.1 and generates a random token per launch.
API calls must send it as a bearer header or as the cookie set by visiting
`/auth?token=...`. The Host header must be a loopback name, which blocks DNS
rebinding from web pages. Runs execute as asyncio tasks in the server process;
the UI polls `GET /api/runs/{id}` for progress.

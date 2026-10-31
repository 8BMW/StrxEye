# Contributing

Thanks for helping. A few things keep the project useful and maintainable.

## Ground rules

- Collectors report what a source returned. Never synthesise, guess or
  backfill data a source did not return. "No data" is a valid result.
- Every observation needs a source, method and, when there was a response,
  stored evidence. Keep confidence below 1.0 when the source cannot prove the
  fact (PTR records, CT-derived subdomains, self-reported registrant data).
- Do not add features for tracking private individuals, collecting personal
  contact data, bypassing authentication or rate limits, or evading detection.
- Anything that contacts the target directly must set `direct = True`.
- No telemetry, analytics or network calls outside of collectors.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cd apps/desktop && npm ci
```

## Checks

Run before opening a pull request:

```bash
ruff check src tests
pytest
cd apps/desktop && npm run typecheck && npm test
```

New collectors need unit tests with mocked responses (`respx` for HTTP, the
`FakeResolver` in `tests/conftest.py` for DNS) covering a normal response, an
empty one and a failure. A test in `tests/test_live.py` is welcome but optional.

## Code style

- Python: ruff, 100 columns, type hints on public functions.
- TypeScript: strict mode; keep logic that can be tested without a DOM in
  plain modules (see `graphModel.ts`).
- Comments explain why, not what: tradeoffs, edge cases and security reasons.
- Error messages say what went wrong and what the user can do about it.

## Commits and pull requests

Write commit messages that describe the change ("rdap: walk up to the
registered domain on 404"), keep pull requests focused, and update
`CHANGELOG.md` under *Unreleased* for user-visible changes.

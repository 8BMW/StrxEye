"""The ``strxeye`` command.

Exit codes:
  0  success (including "nothing found")
  1  completed, but at least one collector failed or timed out
  2  invalid input or usage
  3  every collector failed
  4  investigation, run or evidence not found
  130 interrupted
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .. import __version__
from ..collectors import registry
from ..config import (
    config_path,
    database_path,
    load_settings,
    save_settings,
    set_value,
)
from ..engine import Engine, EngineError, RunEvent, RunOptions, RunReport
from ..models import EntityType
from ..storage import NotFoundError, Store
from ..targets import TargetError, parse_target
from .render import print_results, short

EXIT_PARTIAL, EXIT_USAGE, EXIT_FAILED, EXIT_NOT_FOUND, EXIT_INTERRUPTED = 1, 2, 3, 4, 130

app = typer.Typer(no_args_is_help=True, add_completion=False, rich_markup_mode=None,
                  help="STRX EYE: OSINT collection and investigation from the command line.")
investigate_app = typer.Typer(no_args_is_help=True, help="Create, run and inspect investigations.")
graph_app = typer.Typer(no_args_is_help=True, help="Export investigation graphs.")
plugins_app = typer.Typer(no_args_is_help=True, help="Discover and trust collector plugins.")
config_app = typer.Typer(no_args_is_help=True, help="Show and change settings.")
app.add_typer(investigate_app, name="investigate")
app.add_typer(graph_app, name="graph")
app.add_typer(plugins_app, name="plugins")
app.add_typer(config_app, name="config")

out = Console(highlight=False, soft_wrap=False)
err = Console(stderr=True, highlight=False)

JsonOpt = Annotated[bool, typer.Option("--json", help="Print machine-readable JSON.")]
CollectorsOpt = Annotated[str | None, typer.Option(
    "--collectors", "-c", help="Comma-separated collector names (default: all applicable).")]
DirectOpt = Annotated[bool, typer.Option(
    "--direct", help="Allow collectors that connect to the target's own servers (HTTP, TLS).")]
ExpandOpt = Annotated[bool, typer.Option(
    "--expand", help="Also collect ASN, network owner and PTR for discovered IP addresses.")]
SaveOpt = Annotated[str | None, typer.Option(
    "--save", help="Store the results in this investigation (ID or ID prefix).")]
VerboseOpt = Annotated[bool, typer.Option("--verbose", "-v", help="Show every value.")]


def fail(message: str, code: int = EXIT_USAGE) -> typer.Exit:
    err.print(f"[red]error:[/red] {message}")
    return typer.Exit(code)


def open_store() -> Store:
    store = Store(database_path())
    return store


def make_engine(store: Store | None = None) -> Engine:
    return Engine(load_settings(), store)


def version_callback(value: bool) -> None:
    if value:
        out.print(f"strxeye {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[bool, typer.Option("--version", callback=version_callback,
                                          is_eager=True, help="Show version and exit.")] = False,
) -> None:
    pass


# Collection -----------------------------------------------------------------


def _collect(raw: str, expected: EntityType | None, collectors: str | None, direct: bool,
             expand: bool, save: str | None, as_json: bool, verbose: bool) -> None:
    try:
        target = parse_target(raw, expected)
    except TargetError as exc:
        raise fail(str(exc)) from None
    options = RunOptions(
        collectors=[c.strip() for c in collectors.split(",") if c.strip()] if collectors else None,
        direct=direct, expand=expand)

    store = open_store() if save else None
    inv_id = None
    if store and save:
        try:
            inv_id = store.resolve_investigation_id(save)
        except NotFoundError as exc:
            raise fail(str(exc), EXIT_NOT_FOUND) from None
    engine = make_engine(store)

    running: set[str] = set()
    status = None if as_json or not err.is_terminal else err.status("starting…")

    def on_event(event: RunEvent) -> None:
        label = f"{event.collector}({event.target.value})"
        (running.add if event.kind == "started" else running.discard)(label)
        if status:
            status.update("collecting: " + ", ".join(sorted(running)) if running else "saving…")

    try:
        if status:
            status.start()
        report = asyncio.run(engine.run(target, options, investigation_id=inv_id,
                                        on_event=on_event))
    except EngineError as exc:
        raise fail(str(exc)) from None
    except KeyboardInterrupt:
        raise fail("interrupted", EXIT_INTERRUPTED) from None
    finally:
        if status:
            status.stop()

    if as_json:
        out.print_json(json.dumps({
            "target": target.model_dump(mode="json"),
            "run_id": report.run_id,
            "investigation_id": inv_id,
            "results": [r.model_dump(mode="json", exclude={"evidence"}) for r in report.results],
        }))
    else:
        print_results(out, report.results, verbose)
        if inv_id:
            out.print(f"\nSaved to investigation {inv_id} as run {report.run_id}.")
        skipped_direct = not (direct or engine.settings.collection.allow_direct) and any(
            c.direct and c.supports(target) for c in engine.collectors.values())
        if skipped_direct:
            err.print("[dim]Direct collectors (http, tls) were skipped; add --direct to run "
                      "them.[/dim]")
    raise typer.Exit(exit_code(report))


def exit_code(report: RunReport) -> int:
    if not report.results:
        return 0
    failed = len(report.failed)
    if failed == len(report.results):
        return EXIT_FAILED
    return EXIT_PARTIAL if failed else 0


@app.command()
def domain(name: str, collectors: CollectorsOpt = None, direct: DirectOpt = False,
           expand: ExpandOpt = False, save: SaveOpt = None, json_: JsonOpt = False,
           verbose: VerboseOpt = False) -> None:
    """Collect everything available about a domain."""
    _collect(name, EntityType.DOMAIN, collectors, direct, expand, save, json_, verbose)


@app.command()
def ip(address: str, collectors: CollectorsOpt = None, save: SaveOpt = None,
       json_: JsonOpt = False, verbose: VerboseOpt = False) -> None:
    """Network owner, BGP origin and reverse DNS for an IPv4 or IPv6 address."""
    _collect(address, EntityType.IP, collectors, False, False, save, json_, verbose)


@app.command()
def asn(number: str, save: SaveOpt = None, json_: JsonOpt = False) -> None:
    """Holder and name of an autonomous system (e.g. AS13335)."""
    _collect(number, EntityType.ASN, None, False, False, save, json_, False)


@app.command()
def dns(name: str, save: SaveOpt = None, json_: JsonOpt = False, verbose: VerboseOpt = False):
    """DNS records only."""
    _collect(name, EntityType.DOMAIN, "dns", False, False, save, json_, verbose)


@app.command()
def cert(name: str, direct: DirectOpt = False, save: SaveOpt = None, json_: JsonOpt = False,
         verbose: VerboseOpt = False) -> None:
    """Certificates from CT logs (and the served certificate with --direct)."""
    _collect(name, EntityType.DOMAIN, "crtsh,tls" if direct else "crtsh", direct, False, save,
             json_, verbose)


@app.command()
def lookup(target: str, collectors: CollectorsOpt = None, direct: DirectOpt = False,
           expand: ExpandOpt = False, save: SaveOpt = None, json_: JsonOpt = False,
           verbose: VerboseOpt = False) -> None:
    """Detect the target type (domain, IP, ASN or URL) and collect."""
    _collect(target, None, collectors, direct, expand, save, json_, verbose)


@app.command("collectors")
def list_collectors(json_: JsonOpt = False) -> None:
    """List available collectors and the services each one contacts."""
    items = [c.describe() for c in registry(load_settings()).values()]
    if json_:
        out.print_json(json.dumps(items))
        return
    table = Table(show_edge=False, pad_edge=False)
    for col in ("name", "accepts", "contacts", "direct", "description"):
        table.add_column(col, overflow="fold")
    for c in items:
        table.add_row(c["name"], ", ".join(c["accepts"]), ", ".join(c["sources"]) or "target",
                      "yes" if c["direct"] else "no", c["description"])
    out.print(table)


# Investigations ---------------------------------------------------------------


def _resolve(store: Store, ref: str) -> str:
    try:
        return store.resolve_investigation_id(ref)
    except NotFoundError as exc:
        raise fail(str(exc), EXIT_NOT_FOUND) from None


@investigate_app.command("create")
def investigate_create(name: str, description: Annotated[str, typer.Option(
        "--description", "-d")] = "", json_: JsonOpt = False) -> None:
    """Create an empty investigation."""
    try:
        inv = open_store().create_investigation(name, description)
    except ValueError as exc:
        raise fail(str(exc)) from None
    if json_:
        out.print_json(inv.model_dump_json())
    else:
        out.print(f"Created investigation {inv.id} ({inv.name}).")
        out.print(f"Next: strxeye investigate run {inv.id} example.com")


@investigate_app.command("list")
def investigate_list(json_: JsonOpt = False) -> None:
    """List investigations, most recently updated first."""
    rows = open_store().list_investigations()
    if json_:
        out.print_json(json.dumps(rows))
        return
    if not rows:
        out.print('No investigations yet. Create one with: strxeye investigate create "Name"')
        return
    table = Table(show_edge=False, pad_edge=False)
    for col in ("id", "name", "entities", "relationships", "runs", "updated (UTC)"):
        table.add_column(col)
    for r in rows:
        table.add_row(r["id"], r["name"], str(r["entity_count"]), str(r["relationship_count"]),
                      str(r["run_count"]), r["updated_at"][:19])
    out.print(table)


@investigate_app.command("show")
def investigate_show(case_id: str, json_: JsonOpt = False) -> None:
    """Summary of an investigation: seeds, entity counts and runs."""
    store = open_store()
    inv_id = _resolve(store, case_id)
    inv = store.get_investigation(inv_id)
    runs = store.list_runs(inv_id)
    counts = store.counts(inv_id)
    if json_:
        out.print_json(json.dumps({**inv.model_dump(mode="json"), "entity_counts": counts,
                                   "runs": runs}))
        return
    out.print(f"[bold]{inv.name}[/bold]  ({inv.id})")
    if inv.description:
        out.print(inv.description)
    out.print("Seeds: " + (", ".join(s.key for s in inv.seeds) or "none"))
    out.print("Entities: " + (", ".join(f"{n} {t}" for t, n in sorted(counts.items())) or "none"))
    if runs:
        table = Table(title="Runs", title_justify="left", show_edge=False, pad_edge=False)
        for col in ("run", "target", "started (UTC)", "status", "collectors", "failed"):
            table.add_column(col)
        for r in runs:
            table.add_row(r["id"], r["target_value"], r["started_at"][:19], r["status"],
                          str(r["collector_count"]), str(r["failed_count"]))
        out.print(table)


@investigate_app.command("run")
def investigate_run(case_id: str, target: str, collectors: CollectorsOpt = None,
                    direct: DirectOpt = False, expand: ExpandOpt = False,
                    json_: JsonOpt = False, verbose: VerboseOpt = False) -> None:
    """Collect on a target and save the results to the investigation."""
    _collect(target, None, collectors, direct, expand, case_id, json_, verbose)


@investigate_app.command("entities")
def investigate_entities(
    case_id: str,
    type_: Annotated[str | None, typer.Option("--type", "-t", help="Entity type.")] = None,
    search: Annotated[str | None, typer.Option("--search", "-s")] = None,
    json_: JsonOpt = False,
) -> None:
    """List entities in an investigation."""
    store = open_store()
    inv_id = _resolve(store, case_id)
    if type_ and type_ not in {t.value for t in EntityType}:
        raise fail(f"unknown type '{type_}'; choose from "
                   + ", ".join(t.value for t in EntityType))
    rows = store.entities(inv_id, type_, search)
    if json_:
        out.print_json(json.dumps(rows))
        return
    table = Table(show_edge=False, pad_edge=False)
    for col in ("id", "type", "value", "obs", "links", "last seen (UTC)"):
        table.add_column(col, overflow="fold")
    for r in rows:
        table.add_row(str(r["id"]), r["type"], r["value"], str(r["observations"]),
                      str(r["relationships"]), r["last_seen"][:19])
    out.print(table)


@investigate_app.command("diff")
def investigate_diff(case_id: str, older_run: str, newer_run: str, json_: JsonOpt = False):
    """Compare two runs and show observations that appeared or disappeared."""
    from ..history import diff_runs

    store = open_store()
    inv_id = _resolve(store, case_id)
    try:
        diff = diff_runs(store, inv_id, older_run, newer_run)
    except NotFoundError as exc:
        raise fail(str(exc), EXIT_NOT_FOUND) from None
    if json_:
        out.print_json(json.dumps(diff, default=str))
        return
    out.print(f"{diff['older']['id']} ({diff['older']['started_at'][:19]}) -> "
              f"{diff['newer']['id']} ({diff['newer']['started_at'][:19]})")
    if diff["not_compared"]:
        out.print(f"[yellow]Not compared (failed or absent in one run):[/yellow] "
                  f"{', '.join(diff['not_compared'])}")
    for label, style, rows in (("+", "green", diff["added"]), ("-", "red", diff["removed"])):
        for row in rows:
            out.print(f"[{style}]{label} {row['entity']}  {row['kind']}  "
                      f"{short(row['value'], 100)}[/{style}]")
    out.print(f"{len(diff['added'])} added, {len(diff['removed'])} removed, "
              f"{diff['unchanged']} unchanged")


@investigate_app.command("delete")
def investigate_delete(case_id: str, yes: Annotated[bool, typer.Option(
        "--yes", "-y", help="Do not ask for confirmation.")] = False) -> None:
    """Delete an investigation and all its evidence from the local database."""
    store = open_store()
    inv_id = _resolve(store, case_id)
    inv = store.get_investigation(inv_id)
    if not yes and not typer.confirm(f"Delete '{inv.name}' ({inv_id}) and all its evidence?"):
        raise typer.Exit(1)
    store.delete_investigation(inv_id)
    out.print(f"Deleted {inv_id}.")


@investigate_app.command("evidence")
def investigate_evidence(case_id: str, evidence_id: str) -> None:
    """Print a stored raw response by its SHA-256 (or a unique prefix)."""
    store = open_store()
    inv_id = _resolve(store, case_id)
    matches = [e for e in store.list_evidence(inv_id) if e["id"].startswith(evidence_id.lower())]
    if len(matches) != 1:
        raise fail(f"{len(matches)} evidence items match '{evidence_id}'", EXIT_NOT_FOUND)
    item = store.evidence(inv_id, matches[0]["id"])
    err.print(f"[dim]{item['collector']} · {item['locator']} · {item['collected_at']}[/dim]")
    sys.stdout.write(item["content"] + "\n")


# Graph, reports ---------------------------------------------------------------


def _write(text: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(text)
        return
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    err.print(f"Wrote {output}")


OutputOpt = Annotated[Path | None, typer.Option("--output", "-o", help="Write to a file.")]


@graph_app.command("export")
def graph_export(case_id: str, output: OutputOpt = None, no_inferred: Annotated[
        bool, typer.Option("--no-inferred", help="Leave out inferred relationships.")] = False):
    """Export the investigation graph as JSON (nodes, edges, provenance)."""
    from ..graph import build_graph

    store = open_store()
    data = build_graph(store, _resolve(store, case_id), include_inferred=not no_inferred)
    _write(json.dumps(data, indent=2, default=str), output)


@app.command()
def report(case_id: str, format: Annotated[str, typer.Option(
        "--format", "-f", help="html, json or csv")] = "html", output: OutputOpt = None) -> None:
    """Generate a report for an investigation."""
    from ..reporting import FORMATS, render

    if format == "pdf":
        raise fail("PDF output is not built in yet. Generate HTML and use your browser's "
                   "Print > Save as PDF; the report has print styles.")
    if format not in FORMATS:
        raise fail(f"unknown format '{format}'; choose one of {', '.join(FORMATS)}")
    store = open_store()
    _write(render(store, _resolve(store, case_id), format, load_settings()), output)


# Plugins ----------------------------------------------------------------------


@plugins_app.command("list")
def plugins_list(json_: JsonOpt = False) -> None:
    """Show installed plugins and whether they are trusted. Does not import them."""
    from ..plugins import discover, is_trusted

    settings = load_settings()
    rows = [{"name": p.name, "distribution": p.distribution, "version": p.version,
             "entry_point": p.target, "trusted": is_trusted(p, settings)} for p in discover()]
    if json_:
        out.print_json(json.dumps(rows))
        return
    if not rows:
        out.print("No collector plugins are installed. See docs/plugins.md to write one.")
        return
    table = Table(show_edge=False, pad_edge=False)
    for col in ("name", "package", "version", "trusted"):
        table.add_column(col)
    for r in rows:
        table.add_row(r["name"], r["distribution"], r["version"], "yes" if r["trusted"] else "no")
    out.print(table)


@plugins_app.command("trust")
def plugins_trust(name: str, yes: Annotated[bool, typer.Option("--yes", "-y")] = False) -> None:
    """Allow an installed plugin to run. Plugins run with your user's permissions."""
    from ..plugins import discover

    matches = [p for p in discover() if p.name == name]
    if not matches:
        raise fail(f"no installed plugin named '{name}'", EXIT_NOT_FOUND)
    plugin = matches[0]
    err.print(f"[yellow]Warning:[/yellow] {plugin.distribution} {plugin.version} will run as "
              "Python code with your user account's permissions, including network and file "
              "access. Only trust plugins whose source you have reviewed or whose author you "
              "trust.")
    if not yes and not typer.confirm(f"Trust {plugin.trust_key}?"):
        raise typer.Exit(1)
    settings = load_settings()
    trusted = [t for t in settings.plugins.trusted if not t.startswith(f"{name}==")]
    settings.plugins.trusted = [*trusted, plugin.trust_key]
    save_settings(settings)
    Store(database_path()).audit("plugin.trust", None, {"plugin": plugin.trust_key})
    out.print(f"Trusted {plugin.trust_key}.")


@plugins_app.command("untrust")
def plugins_untrust(name: str) -> None:
    """Stop a plugin from running."""
    settings = load_settings()
    before = len(settings.plugins.trusted)
    settings.plugins.trusted = [t for t in settings.plugins.trusted
                                if not t.startswith(f"{name}==")]
    if len(settings.plugins.trusted) == before:
        raise fail(f"'{name}' is not trusted", EXIT_NOT_FOUND)
    save_settings(settings)
    Store(database_path()).audit("plugin.untrust", None, {"plugin": name})
    out.print(f"'{name}' will no longer run.")


# Config -----------------------------------------------------------------------


@config_app.command("show")
def config_show(json_: JsonOpt = False) -> None:
    """Print current settings and where they are stored."""
    settings = load_settings()
    if json_:
        out.print_json(json.dumps({"config_file": str(config_path()),
                                   "database": str(database_path()),
                                   "settings": settings.model_dump()}))
        return
    out.print(f"config file: {config_path()}")
    out.print(f"database:    {database_path()}\n")
    for section, values in settings.model_dump().items():
        for key, value in values.items():
            out.print(f"{section}.{key} = {value!r}")


@config_app.command("set")
def config_set(key: str, value: str) -> None:
    """Change a setting, e.g. 'strxeye config set dns.nameservers 1.1.1.1,9.9.9.9'."""
    try:
        settings = set_value(load_settings(), key, value)
    except (KeyError, ValueError) as exc:
        raise fail(str(exc).strip("'\"")) from None
    path = save_settings(settings)
    out.print(f"{key} updated in {path}")


# Local API for the desktop app ----------------------------------------------------


@app.command()
def serve(
    port: Annotated[int, typer.Option(help="Port on 127.0.0.1 (0 picks a free port).")] = 8765,
    token: Annotated[str | None, typer.Option(
        envvar="STRXEYE_API_TOKEN", help="API token (default: random, printed at start).")] = None,
) -> None:
    """Run the local API used by the desktop app. Listens on 127.0.0.1 only."""
    try:
        from ..server import run_server
    except ImportError:
        raise fail("the API server needs extra packages: pip install 'strxeye[server]'") from None
    run_server(port=port, token=token)


def run() -> None:
    app()


if __name__ == "__main__":
    run()

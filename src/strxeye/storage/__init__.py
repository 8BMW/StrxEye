"""SQLite storage for investigations, runs, evidence and the entity graph.

Observations and relationships are append-only per run: re-running a
collector adds new rows instead of overwriting, which is what makes run-to-
run comparison possible. Entities are unique per investigation.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from ..models import CollectorResult, EntityRef, Investigation, utcnow
from .migrations import MIGRATIONS


class NotFoundError(LookupError):
    pass


def _now() -> str:
    return utcnow().isoformat()


def _iso(value: datetime) -> str:
    return value.isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, default=str, sort_keys=True)


class Store:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        # One connection shared across threads (the local API runs request
        # handlers in a thread pool), serialised by a lock. Investigations
        # are small enough that this is never the bottleneck; the network is.
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._conn.execute("PRAGMA foreign_keys = ON")
        # Overwrite deleted content with zeros so deleted investigations do
        # not linger in free pages of the database file.
        self._conn.execute("PRAGMA secure_delete = ON")
        if str(path) != ":memory:":
            self._conn.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise

    def _query(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def _migrate(self) -> None:
        with self._lock:
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version > len(MIGRATIONS):
                raise RuntimeError(
                    f"database {self.path} was created by a newer STRX EYE "
                    f"(schema {version}); upgrade before opening it")
            for number, sql in enumerate(MIGRATIONS[version:], start=version + 1):
                self._conn.executescript(f"BEGIN;\n{sql}\nPRAGMA user_version = {number};\nCOMMIT;")

    @property
    def schema_version(self) -> int:
        return self._query("PRAGMA user_version")[0][0]

    # Investigations -------------------------------------------------------

    def create_investigation(self, name: str, description: str = "") -> Investigation:
        name = name.strip()
        if not name:
            raise ValueError("investigation name cannot be empty")
        if len(name) > 200:
            raise ValueError("investigation name is limited to 200 characters")
        inv_id = uuid.uuid4().hex[:12]
        now = _now()
        with self._tx() as db:
            db.execute("INSERT INTO investigations VALUES (?, ?, ?, ?, ?)",
                       (inv_id, name, description.strip(), now, now))
        self.audit("investigation.create", inv_id, {"name": name})
        return self.get_investigation(inv_id)

    def resolve_investigation_id(self, ref: str) -> str:
        """Accept a full ID or an unambiguous prefix (as git does)."""
        ref = ref.strip().lower()
        if len(ref) < 4:
            raise NotFoundError("investigation IDs need at least 4 characters")
        rows = self._query("SELECT id FROM investigations WHERE id LIKE ? ESCAPE '\\'",
                           (ref.replace("%", "\\%").replace("_", "\\_") + "%",))
        if not rows:
            raise NotFoundError(f"no investigation matches '{ref}'")
        if len(rows) > 1:
            raise NotFoundError(f"'{ref}' matches {len(rows)} investigations; use more characters")
        return rows[0]["id"]

    def get_investigation(self, ref: str) -> Investigation:
        inv_id = self.resolve_investigation_id(ref)
        row = self._query("SELECT * FROM investigations WHERE id = ?", (inv_id,))[0]
        seeds = [EntityRef(type=r["type"], value=r["value"]) for r in self._query(
            "SELECT type, value FROM seeds WHERE investigation_id = ? ORDER BY added_at",
            (inv_id,))]
        return Investigation(**dict(row), seeds=seeds)

    def list_investigations(self) -> list[dict[str, Any]]:
        rows = self._query("""
            SELECT i.*,
              (SELECT COUNT(*) FROM entities e WHERE e.investigation_id = i.id) AS entity_count,
              (SELECT COUNT(*) FROM relationships r WHERE r.investigation_id = i.id)
                  AS relationship_count,
              (SELECT COUNT(*) FROM runs r WHERE r.investigation_id = i.id) AS run_count,
              (SELECT MAX(started_at) FROM runs r WHERE r.investigation_id = i.id) AS last_run_at
            FROM investigations i ORDER BY i.updated_at DESC""")
        return [dict(r) for r in rows]

    def rename_investigation(self, inv_id: str, name: str, description: str | None = None) -> None:
        if not name.strip():
            raise ValueError("investigation name cannot be empty")
        with self._tx() as db:
            db.execute("UPDATE investigations SET name = ?, description = COALESCE(?, description),"
                       " updated_at = ? WHERE id = ?", (name.strip(), description, _now(), inv_id))

    def delete_investigation(self, inv_id: str) -> None:
        inv_id = self.resolve_investigation_id(inv_id)
        with self._tx() as db:
            db.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
        self.audit("investigation.delete", inv_id, {})
        with self._lock:
            # VACUUM rebuilds the file without the freed pages. Together with
            # secure_delete this is as far as SQLite can go; copies held by
            # backups, sync clients or SSD wear levelling are out of reach.
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.execute("VACUUM")

    def add_seed(self, inv_id: str, ref: EntityRef) -> None:
        with self._tx() as db:
            db.execute("INSERT OR IGNORE INTO seeds VALUES (?, ?, ?, ?)",
                       (inv_id, ref.type.value, ref.value, _now()))
            db.execute("UPDATE investigations SET updated_at = ? WHERE id = ?", (_now(), inv_id))

    # Runs -----------------------------------------------------------------

    def start_run(self, inv_id: str, target: EntityRef, options: dict[str, Any]) -> str:
        run_id = uuid.uuid4().hex[:12]
        with self._tx() as db:
            db.execute(
                "INSERT INTO runs (id, investigation_id, target_type, target_value, options,"
                " status, started_at) VALUES (?, ?, ?, ?, ?, 'running', ?)",
                (run_id, inv_id, target.type.value, target.value, _json(options), _now()))
            db.execute("UPDATE investigations SET updated_at = ? WHERE id = ?", (_now(), inv_id))
        self.audit("run.start", inv_id, {"run": run_id, "target": target.key, **options})
        return run_id

    def finish_run(self, run_id: str, status: str) -> None:
        with self._tx() as db:
            db.execute("UPDATE runs SET status = ?, finished_at = ? WHERE id = ?",
                       (status, _now(), run_id))

    def fail_interrupted_runs(self) -> int:
        """Runs left 'running' by a crash or kill cannot resume; mark them."""
        with self._tx() as db:
            cur = db.execute("UPDATE runs SET status = 'interrupted', finished_at = ?"
                             " WHERE status = 'running'", (_now(),))
            return cur.rowcount

    def get_run(self, run_id: str) -> dict[str, Any]:
        rows = self._query("SELECT * FROM runs WHERE id = ?", (run_id,))
        if not rows:
            raise NotFoundError(f"no run with id '{run_id}'")
        run = dict(rows[0])
        run["options"] = json.loads(run["options"])
        run["collectors"] = [
            {**dict(r), "notes": json.loads(r["notes"])}
            for r in self._query("SELECT * FROM collector_runs WHERE run_id = ? ORDER BY id",
                                 (run_id,))
        ]
        return run

    def list_runs(self, inv_id: str) -> list[dict[str, Any]]:
        rows = self._query("""
            SELECT r.*,
              (SELECT COUNT(*) FROM collector_runs c WHERE c.run_id = r.id) AS collector_count,
              (SELECT COUNT(*) FROM collector_runs c WHERE c.run_id = r.id
                 AND c.status IN ('error', 'timeout')) AS failed_count,
              (SELECT COUNT(*) FROM observations o WHERE o.run_id = r.id) AS observation_count
            FROM runs r WHERE investigation_id = ? ORDER BY started_at DESC""", (inv_id,))
        return [{**dict(r), "options": json.loads(r["options"])} for r in rows]

    # Results --------------------------------------------------------------

    def _entity_id(self, db: sqlite3.Connection, inv_id: str, ref: EntityRef,
                   attributes: dict[str, Any] | None, seen: str) -> int:
        row = db.execute("SELECT id, attributes FROM entities WHERE investigation_id = ?"
                         " AND type = ? AND value = ?", (inv_id, ref.type.value, ref.value)
                         ).fetchone()
        if row is None:
            cur = db.execute(
                "INSERT INTO entities (investigation_id, type, value, attributes, first_seen,"
                " last_seen) VALUES (?, ?, ?, ?, ?, ?)",
                (inv_id, ref.type.value, ref.value, _json(attributes or {}), seen, seen))
            return cur.lastrowid
        merged = json.loads(row["attributes"])
        merged.update({k: v for k, v in (attributes or {}).items() if v not in (None, "", [])})
        db.execute("UPDATE entities SET attributes = ?, last_seen = ? WHERE id = ?",
                   (_json(merged), seen, row["id"]))
        return row["id"]

    def save_result(self, inv_id: str, run_id: str, result: CollectorResult) -> None:
        seen = _iso(result.finished_at)
        with self._tx() as db:
            db.execute(
                "INSERT INTO collector_runs (run_id, collector, target_type, target_value, status,"
                " started_at, finished_at, error, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, result.collector, result.target.type.value, result.target.value,
                 result.status.value, _iso(result.started_at), seen, result.error,
                 _json(result.notes)))
            for ev in result.evidence:
                db.execute("INSERT OR IGNORE INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?)",
                           (inv_id, ev.id, ev.collector, ev.locator, ev.content_type, ev.content,
                            _iso(ev.collected_at)))
            ids: dict[EntityRef, int] = {}

            def entity_id(ref: EntityRef) -> int:
                if ref not in ids:
                    ids[ref] = self._entity_id(db, inv_id, ref, None, seen)
                return ids[ref]

            for entity in result.entities:
                ids[entity.ref] = self._entity_id(db, inv_id, entity.ref, entity.attributes, seen)
            for obs in result.observations:
                db.execute(
                    "INSERT INTO observations (investigation_id, run_id, entity_id, kind, value,"
                    " source, method, source_url, confidence, evidence_id, collected_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (inv_id, run_id, entity_id(obs.entity), obs.kind, _json(obs.value),
                     obs.source, obs.method, obs.source_url, obs.confidence, obs.evidence_id,
                     _iso(obs.collected_at)))
            for rel in result.relationships:
                db.execute(
                    "INSERT INTO relationships (investigation_id, run_id, source_id, target_id,"
                    " type, origin, confidence, evidence_id, collected_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (inv_id, run_id, entity_id(rel.source), entity_id(rel.target),
                     rel.type.value, rel.origin, rel.confidence, rel.evidence_id,
                     _iso(rel.collected_at)))

    # Reading --------------------------------------------------------------

    def entities(self, inv_id: str, type: str | None = None, search: str | None = None,
                 limit: int = 1000, offset: int = 0) -> list[dict[str, Any]]:
        sql = """SELECT e.*,
                   (SELECT COUNT(*) FROM observations o WHERE o.entity_id = e.id) AS observations,
                   (SELECT COUNT(DISTINCT r.id) FROM relationships r
                      WHERE r.source_id = e.id OR r.target_id = e.id) AS relationships
                 FROM entities e WHERE e.investigation_id = :inv"""
        params: dict[str, Any] = {"inv": inv_id, "limit": limit, "offset": offset}
        if type:
            sql += " AND e.type = :type"
            params["type"] = type
        if search:
            sql += " AND e.value LIKE :search ESCAPE '\\'"
            params["search"] = "%" + search.replace("%", "\\%").replace("_", "\\_") + "%"
        sql += " ORDER BY e.type, e.value LIMIT :limit OFFSET :offset"
        return [{**dict(r), "attributes": json.loads(r["attributes"])}
                for r in self._query(sql, params)]

    def find_entity(self, inv_id: str, ref: EntityRef) -> int | None:
        rows = self._query("SELECT id FROM entities WHERE investigation_id = ? AND type = ?"
                           " AND value = ?", (inv_id, ref.type.value, ref.value))
        return rows[0]["id"] if rows else None

    def entity_detail(self, inv_id: str, entity_id: int) -> dict[str, Any]:
        rows = self._query("SELECT * FROM entities WHERE id = ? AND investigation_id = ?",
                           (entity_id, inv_id))
        if not rows:
            raise NotFoundError(f"no entity {entity_id} in this investigation")
        entity = {**dict(rows[0]), "attributes": json.loads(rows[0]["attributes"])}
        entity["observations"] = [
            {**dict(r), "value": json.loads(r["value"])}
            for r in self._query("SELECT * FROM observations WHERE entity_id = ?"
                                 " ORDER BY kind, collected_at DESC", (entity_id,))]
        entity["relationships"] = [dict(r) for r in self._query("""
            SELECT r.type, r.origin, r.confidence, r.evidence_id, r.collected_at, r.run_id,
                   CASE WHEN r.source_id = :id THEN 'out' ELSE 'in' END AS direction,
                   o.id AS other_id, o.type AS other_type, o.value AS other_value
            FROM relationships r
            JOIN entities o ON o.id = CASE WHEN r.source_id = :id THEN r.target_id
                                           ELSE r.source_id END
            WHERE r.source_id = :id OR r.target_id = :id
            ORDER BY r.type, o.value""", {"id": entity_id})]
        return entity

    def all_relationships(self, inv_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._query("""
            SELECT r.*, s.type AS source_type, s.value AS source_value,
                   t.type AS target_type, t.value AS target_value
            FROM relationships r
            JOIN entities s ON s.id = r.source_id
            JOIN entities t ON t.id = r.target_id
            WHERE r.investigation_id = ? ORDER BY r.id""", (inv_id,))]

    def all_observations(self, inv_id: str, run_id: str | None = None) -> list[dict[str, Any]]:
        sql = """SELECT o.*, e.type AS entity_type, e.value AS entity_value
                 FROM observations o JOIN entities e ON e.id = o.entity_id
                 WHERE o.investigation_id = ?"""
        params: tuple = (inv_id,)
        if run_id:
            sql += " AND o.run_id = ?"
            params += (run_id,)
        return [{**dict(r), "value": json.loads(r["value"])}
                for r in self._query(sql + " ORDER BY e.type, e.value, o.kind", params)]

    def evidence(self, inv_id: str, evidence_id: str) -> dict[str, Any]:
        rows = self._query("SELECT * FROM evidence WHERE investigation_id = ? AND id = ?",
                           (inv_id, evidence_id))
        if not rows:
            raise NotFoundError(f"no evidence '{evidence_id}' in this investigation")
        return dict(rows[0])

    def list_evidence(self, inv_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._query(
            "SELECT id, collector, locator, content_type, collected_at, LENGTH(content) AS size"
            " FROM evidence WHERE investigation_id = ? ORDER BY collected_at DESC", (inv_id,))]

    def counts(self, inv_id: str) -> dict[str, int]:
        rows = self._query("SELECT type, COUNT(*) AS n FROM entities WHERE investigation_id = ?"
                           " GROUP BY type", (inv_id,))
        return {r["type"]: r["n"] for r in rows}

    # Audit ----------------------------------------------------------------

    def audit(self, action: str, inv_id: str | None, detail: dict[str, Any]) -> None:
        with self._tx() as db:
            db.execute("INSERT INTO audit_log (at, action, investigation_id, detail)"
                       " VALUES (?, ?, ?, ?)", (_now(), action, inv_id, _json(detail)))

    def audit_log(self, limit: int = 200) -> list[dict[str, Any]]:
        return [{**dict(r), "detail": json.loads(r["detail"])} for r in self._query(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

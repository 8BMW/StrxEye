"""Schema migrations, applied in order. Never edit a migration that has
shipped; add a new one instead."""

MIGRATIONS: list[str] = [
    # 1: initial schema
    """
    CREATE TABLE investigations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE seeds (
        investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        added_at TEXT NOT NULL,
        PRIMARY KEY (investigation_id, type, value)
    );

    CREATE TABLE runs (
        id TEXT PRIMARY KEY,
        investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        target_type TEXT NOT NULL,
        target_value TEXT NOT NULL,
        options TEXT NOT NULL DEFAULT '{}',
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT
    );
    CREATE INDEX runs_investigation ON runs(investigation_id, started_at);

    CREATE TABLE collector_runs (
        id INTEGER PRIMARY KEY,
        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        collector TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_value TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL,
        error TEXT,
        notes TEXT NOT NULL DEFAULT '[]'
    );
    CREATE INDEX collector_runs_run ON collector_runs(run_id);

    CREATE TABLE entities (
        id INTEGER PRIMARY KEY,
        investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        attributes TEXT NOT NULL DEFAULT '{}',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE (investigation_id, type, value)
    );

    CREATE TABLE evidence (
        investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        id TEXT NOT NULL,
        collector TEXT NOT NULL,
        locator TEXT NOT NULL,
        content_type TEXT NOT NULL,
        content TEXT NOT NULL,
        collected_at TEXT NOT NULL,
        PRIMARY KEY (investigation_id, id)
    );

    CREATE TABLE observations (
        id INTEGER PRIMARY KEY,
        investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        source TEXT NOT NULL,
        method TEXT NOT NULL,
        source_url TEXT,
        confidence REAL NOT NULL,
        evidence_id TEXT,
        collected_at TEXT NOT NULL
    );
    CREATE INDEX observations_entity ON observations(entity_id);
    CREATE INDEX observations_run ON observations(run_id);

    CREATE TABLE relationships (
        id INTEGER PRIMARY KEY,
        investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        source_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
        target_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        origin TEXT NOT NULL,
        confidence REAL NOT NULL,
        evidence_id TEXT,
        collected_at TEXT NOT NULL
    );
    CREATE INDEX relationships_investigation ON relationships(investigation_id);
    CREATE INDEX relationships_source ON relationships(source_id);
    CREATE INDEX relationships_target ON relationships(target_id);

    CREATE TABLE audit_log (
        id INTEGER PRIMARY KEY,
        at TEXT NOT NULL,
        action TEXT NOT NULL,
        investigation_id TEXT,
        detail TEXT NOT NULL DEFAULT '{}'
    );
    """,
]

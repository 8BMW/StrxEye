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
    # 2: full-text search over entity values, observation values and raw
    # evidence. The trigram tokenizer gives substring matching, which is
    # what analysts expect for IPs, hostnames and hashes.
    """
    CREATE VIRTUAL TABLE search_index USING fts5(
        text, investigation_id UNINDEXED, kind UNINDEXED, ref UNINDEXED,
        tokenize = 'trigram'
    );
    INSERT INTO search_index (text, investigation_id, kind, ref)
        SELECT value, investigation_id, 'entity', id FROM entities;
    INSERT INTO search_index (text, investigation_id, kind, ref)
        SELECT value, investigation_id, 'observation', id FROM observations;
    INSERT INTO search_index (text, investigation_id, kind, ref)
        SELECT content, investigation_id, 'evidence', id FROM evidence;

    CREATE TRIGGER entities_search AFTER INSERT ON entities BEGIN
        INSERT INTO search_index (text, investigation_id, kind, ref)
        VALUES (new.value, new.investigation_id, 'entity', new.id);
    END;
    CREATE TRIGGER observations_search AFTER INSERT ON observations BEGIN
        INSERT INTO search_index (text, investigation_id, kind, ref)
        VALUES (new.value, new.investigation_id, 'observation', new.id);
    END;
    CREATE TRIGGER evidence_search AFTER INSERT ON evidence BEGIN
        INSERT INTO search_index (text, investigation_id, kind, ref)
        VALUES (new.content, new.investigation_id, 'evidence', new.id);
    END;
    """,
    # 3: monitoring. A watch re-collects a target on a schedule; each run is
    # compared with the previous one and notable changes become alerts.
    """
    CREATE TABLE watches (
        id INTEGER PRIMARY KEY,
        investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        target_type TEXT NOT NULL,
        target_value TEXT NOT NULL,
        interval_hours REAL NOT NULL,
        options TEXT NOT NULL DEFAULT '{}',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        last_run_at TEXT,
        last_run_id TEXT,
        last_error TEXT,
        next_run_at TEXT NOT NULL,
        UNIQUE (investigation_id, target_type, target_value)
    );
    CREATE TABLE alerts (
        id INTEGER PRIMARY KEY,
        investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        watch_id INTEGER REFERENCES watches(id) ON DELETE SET NULL,
        run_id TEXT,
        created_at TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT NOT NULL DEFAULT '{}',
        read_at TEXT
    );
    CREATE INDEX alerts_unread ON alerts(read_at, created_at);
    """,
    # 4: remember which target each observation's collector run was for, so
    # run comparisons can match (collector, target) pairs exactly. Older rows
    # keep NULL and are compared by collector name only.
    """
    ALTER TABLE observations ADD COLUMN collector_target TEXT;
    """,
]

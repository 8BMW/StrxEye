import { useEffect, useState } from "react";
import { api } from "../api";
import { EvidenceViewer } from "../components/EvidenceViewer";
import { EmptyState, ErrorBanner, Spinner, TypeBadge } from "../components/ui";
import { formatTime, href, navigate } from "../lib";
import type { SearchResults } from "../types";

/** Renders a snippet with the matched text (between [ and ]) highlighted. */
function Snippet({ text }: { text: string }) {
  const parts = text.split(/(\[[^\]]*\])/);
  return (
    <span className="mono break-all text-muted">
      {parts.map((p, i) => p.startsWith("[") && p.endsWith("]")
        ? <mark key={i} className="rounded bg-accent/25 px-0.5 text-fg">{p.slice(1, -1)}</mark>
        : <span key={i}>{p}</span>)}
    </span>
  );
}

export function SearchPage({ initial }: { initial?: string }) {
  const [query, setQuery] = useState(initial ?? "");
  const [results, setResults] = useState<SearchResults | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [evidence, setEvidence] = useState<{ inv: string; id: string } | null>(null);

  const run = async (text: string) => {
    if (text.trim().length < 3) {
      setError("Type at least 3 characters.");
      return;
    }
    setBusy(true);
    setError(null);
    try { setResults(await api.search(text.trim())); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };

  useEffect(() => { if (initial) run(initial); }, [initial]);

  const total = results ? results.entities.length + results.observations.length + results.evidence.length : 0;

  return (
    <div className="flex h-full flex-col">
      <header className="border-b border-line px-6 py-4">
        <h1 className="text-lg font-semibold">Search</h1>
        <p className="text-muted">Substring search across every investigation: entity values, collected values and raw evidence.</p>
        <form className="mt-3 flex max-w-2xl gap-2" onSubmit={(e) => {
          e.preventDefault();
          navigate({ page: "search", q: query.trim() });
          run(query);
        }}>
          <input className="input mono" autoFocus value={query} onChange={(e) => setQuery(e.target.value)}
            placeholder="IP, hostname, hash, certificate serial, any text in evidence…" aria-label="Search text" />
          <button className="btn-primary" disabled={busy}>{busy ? <Spinner /> : null} Search</button>
        </form>
      </header>
      <div className="min-h-0 flex-1 overflow-auto p-6">
        {error && <ErrorBanner message={error} />}
        {results && total === 0 && <EmptyState title="No matches">Nothing in any investigation contains “{query}”.</EmptyState>}
        {results && results.entities.length > 0 && (
          <section className="mb-6">
            <h2 className="label mb-2">Entities ({results.entities.length})</h2>
            <ul className="card divide-y divide-line/60">
              {results.entities.map((r) => (
                <li key={`${r.investigation_id}-${r.id}`} className="flex items-center gap-3 px-3 py-2">
                  <TypeBadge type={r.type} />
                  <a className="mono hover:text-accent" href={href({ page: "investigation", id: r.investigation_id, tab: "entities", entity: r.id })}>{r.value}</a>
                  <span className="ml-auto text-xxs text-muted">{r.investigation}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
        {results && results.observations.length > 0 && (
          <section className="mb-6">
            <h2 className="label mb-2">Collected values ({results.observations.length})</h2>
            <ul className="card divide-y divide-line/60">
              {results.observations.map((r) => (
                <li key={`${r.investigation_id}-${r.id}`} className="px-3 py-2">
                  <div className="flex items-center gap-2">
                    <TypeBadge type={r.entity_type} />
                    <a className="mono hover:text-accent" href={href({ page: "investigation", id: r.investigation_id, tab: "entities", entity: r.entity_id })}>{r.entity_value}</a>
                    <span className="mono text-muted">{r.kind}</span>
                    <span className="ml-auto text-xxs text-muted">{r.source} · {r.investigation}</span>
                  </div>
                  <Snippet text={r.snippet} />
                </li>
              ))}
            </ul>
          </section>
        )}
        {results && results.evidence.length > 0 && (
          <section>
            <h2 className="label mb-2">Raw evidence ({results.evidence.length})</h2>
            <ul className="card divide-y divide-line/60">
              {results.evidence.map((r) => (
                <li key={`${r.investigation_id}-${r.id}`} className="px-3 py-2">
                  <div className="flex items-center gap-2">
                    <button className="mono truncate text-left hover:text-accent" onClick={() => setEvidence({ inv: r.investigation_id, id: r.id })}>{r.locator}</button>
                    <span className="ml-auto shrink-0 text-xxs text-muted">{r.collector} · {formatTime(r.collected_at)} · {r.investigation}</span>
                  </div>
                  <Snippet text={r.snippet} />
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
      {evidence && <EvidenceViewer investigationId={evidence.inv} evidenceId={evidence.id} onClose={() => setEvidence(null)} />}
    </div>
  );
}

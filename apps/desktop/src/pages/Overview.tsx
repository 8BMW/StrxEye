import { useMemo, useState } from "react";
import { useApp } from "../App";
import { EmptyState, Icon } from "../components/ui";
import { href, relativeTime, TYPE_COLORS } from "../lib";
import type { EntityType } from "../types";

export function Overview() {
  const { investigations, openNewInvestigation, meta } = useApp();
  const [search, setSearch] = useState("");
  const rows = useMemo(() => {
    const s = search.trim().toLowerCase();
    return s ? investigations.filter((i) => `${i.name} ${i.id} ${i.description}`.toLowerCase().includes(s)) : investigations;
  }, [investigations, search]);

  const totals = investigations.reduce(
    (acc, i) => ({ entities: acc.entities + i.entity_count, links: acc.links + i.relationship_count,
      runs: acc.runs + i.run_count, listed: acc.listed + i.listed_count }),
    { entities: 0, links: 0, runs: 0, listed: 0 },
  );

  return (
    <div className="flex h-full flex-col overflow-auto">
      <header className="flex items-center justify-between border-b border-line px-6 py-4">
        <div>
          <h1 className="text-lg font-semibold">Overview</h1>
          <p className="text-muted">Investigations stored in this workspace.</p>
        </div>
        <button className="btn-primary" onClick={openNewInvestigation}><Icon name="plus" /> New investigation</button>
      </header>

      <div className="grid grid-cols-2 gap-3 px-6 pt-5 lg:grid-cols-5">
        <Stat label="Investigations" value={investigations.length} />
        <Stat label="Entities" value={totals.entities} />
        <Stat label="Relationships" value={totals.links} />
        <Stat label="Collection runs" value={totals.runs} />
        <Stat label="On block lists" value={totals.listed} tone={totals.listed ? "text-bad" : undefined} />
      </div>

      <section className="px-6 py-5">
        {investigations.length === 0 ? (
          <div className="card">
            <EmptyState title="No investigations yet"
              action={<button className="btn-primary" onClick={openNewInvestigation}><Icon name="plus" /> Create the first one</button>}>
              An investigation holds the targets you collect on, every observation with its source, and the graph
              built from them. {meta && `${meta.collectors.length} collectors are available.`}
            </EmptyState>
          </div>
        ) : (
          <div className="card overflow-hidden">
            <div className="flex items-center gap-3 border-b border-line p-3">
              <input className="input max-w-xs" placeholder="Filter investigations" value={search}
                onChange={(e) => setSearch(e.target.value)} aria-label="Filter investigations" />
              <span className="text-muted">{rows.length} of {investigations.length}</span>
            </div>
            <table className="tbl">
              <thead>
                <tr><th>Name</th><th className="w-56">Composition</th><th className="text-right">Entities</th><th className="text-right">Relationships</th>
                  <th className="text-right">Runs</th><th className="text-right">Listed</th><th>Last collection</th></tr>
              </thead>
              <tbody>
                {rows.map((inv) => (
                  <tr key={inv.id} className="hover:bg-raised/60">
                    <td>
                      <a className="font-medium hover:text-accent" href={href({ page: "investigation", id: inv.id, tab: "entities" })}>{inv.name}</a>
                      {inv.description && <div className="max-w-md truncate text-xxs text-muted">{inv.description}</div>}
                    </td>
                    <td><Composition counts={inv.type_counts} total={inv.entity_count} /></td>
                    <td className="text-right tabular-nums">{inv.entity_count}</td>
                    <td className="text-right tabular-nums">{inv.relationship_count}</td>
                    <td className="text-right tabular-nums">{inv.run_count}</td>
                    <td className={`text-right tabular-nums ${inv.listed_count ? "font-semibold text-bad" : "text-muted"}`}>{inv.listed_count}</td>
                    <td className="text-muted">{relativeTime(inv.last_run_at)}</td>
                  </tr>
                ))}
                {rows.length === 0 && <tr><td colSpan={7} className="py-6 text-center text-muted">No investigation matches “{search}”.</td></tr>}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="card px-4 py-3">
      <div className="label">{label}</div>
      <div className={`mt-1 text-2xl font-semibold tabular-nums ${tone ?? ""}`}>{value.toLocaleString()}</div>
    </div>
  );
}

/** Stacked bar of entity types, so an investigation's shape is visible at a glance. */
function Composition({ counts, total }: { counts: Partial<Record<EntityType, number>>; total: number }) {
  if (!total) return <span className="text-xxs text-muted">empty</span>;
  const parts = (Object.entries(counts) as [EntityType, number][]).sort((a, b) => b[1] - a[1]);
  return (
    <div className="flex h-2 w-full overflow-hidden rounded-full bg-line"
      title={parts.map(([t, n]) => `${n} ${t}`).join(", ")} role="img"
      aria-label={parts.map(([t, n]) => `${n} ${t}`).join(", ")}>
      {parts.map(([t, n]) => (
        <span key={t} style={{ width: `${(n / total) * 100}%`, background: TYPE_COLORS[t] }} />
      ))}
    </div>
  );
}

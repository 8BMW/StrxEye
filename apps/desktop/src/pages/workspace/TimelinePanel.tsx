import { useMemo, useState } from "react";
import { api } from "../../api";
import { EvidenceViewer } from "../../components/EvidenceViewer";
import { EmptyState, ErrorBanner, Spinner, TypeBadge } from "../../components/ui";
import { useLoad } from "../../lib";
import type { PanelProps } from "../Workspace";

export function TimelinePanel({ inv }: PanelProps) {
  const events = useLoad(() => api.timeline(inv.id), [inv.id, inv.updated_at]);
  const [filter, setFilter] = useState("");
  const [hideCerts, setHideCerts] = useState(false);
  const [evidence, setEvidence] = useState<string | null>(null);

  const rows = useMemo(() => {
    const f = filter.toLowerCase();
    return (events.data ?? []).filter((e) => (!hideCerts || e.entity_type !== "certificate")
      && (!f || `${e.event} ${e.entity} ${e.detail ?? ""}`.toLowerCase().includes(f)));
  }, [events.data, filter, hideCerts]);

  // Group by year for a readable vertical timeline.
  const byYear = useMemo(() => {
    const groups = new Map<string, typeof rows>();
    for (const e of rows) {
      const year = e.at.slice(0, 4);
      if (!groups.has(year)) groups.set(year, []);
      groups.get(year)!.push(e);
    }
    return [...groups.entries()];
  }, [rows]);

  if (events.error) return <div className="p-6"><ErrorBanner message={events.error} onRetry={events.reload} /></div>;
  if (!events.data) return <div className="p-6 text-muted"><Spinner /> Building timeline</div>;
  if (events.data.length === 0) {
    return <EmptyState title="No dated events yet">Registration dates, certificates, passive DNS, archive captures and threat reports appear here once collected.</EmptyState>;
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b border-line p-3">
        <input className="input max-w-sm" placeholder="Filter events" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter events" />
        <label className="flex items-center gap-1.5">
          <input type="checkbox" className="accent-[rgb(var(--accent))]" checked={hideCerts} onChange={(e) => setHideCerts(e.target.checked)} />
          Hide certificate validity dates
        </label>
        <span className="text-muted">{rows.length} events · dates as reported by each source (UTC)</span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto px-6 py-4">
        {byYear.map(([year, items]) => (
          <section key={year} className="mb-5">
            <h2 className="mb-2 text-[15px] font-semibold text-accent">{year}</h2>
            <ol className="relative space-y-2 border-l border-line pl-5">
              {items.map((e, i) => (
                <li key={`${e.at}-${i}`} className="relative">
                  <span className="absolute -left-[25px] top-1.5 h-2 w-2 rounded-full bg-accent" />
                  <div className="flex flex-wrap items-baseline gap-x-2">
                    <span className="mono text-xxs text-muted">{e.at.slice(0, 10)}</span>
                    <span className="font-medium">{e.event}</span>
                    <TypeBadge type={e.entity_type} />
                    <span className="mono break-all">{e.entity}</span>
                  </div>
                  <div className="flex flex-wrap gap-x-3 text-xxs text-muted">
                    {e.detail && <span className="mono">{e.detail}</span>}
                    <span>source: {e.source}</span>
                    {e.evidence_id && <button className="text-accent hover:underline" onClick={() => setEvidence(e.evidence_id)}>evidence</button>}
                  </div>
                </li>
              ))}
            </ol>
          </section>
        ))}
      </div>
      {evidence && <EvidenceViewer investigationId={inv.id} evidenceId={evidence} onClose={() => setEvidence(null)} />}
    </div>
  );
}

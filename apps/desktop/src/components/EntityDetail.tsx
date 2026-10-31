import { useMemo, useState } from "react";
import { api } from "../api";
import { formatTime, formatValue, humanize, useLoad } from "../lib";
import type { Observation } from "../types";
import { EvidenceViewer } from "./EvidenceViewer";
import { Confidence, ErrorBanner, Spinner, TypeBadge, useToast } from "./ui";

export function EntityDetail({ investigationId, entityId, onSelectEntity, compact = false }: {
  investigationId: string;
  entityId: number;
  onSelectEntity: (id: number) => void;
  compact?: boolean;
}) {
  const toast = useToast();
  const detail = useLoad(() => api.entity(investigationId, entityId), [investigationId, entityId]);
  const [evidence, setEvidence] = useState<string | null>(null);
  const [relFilter, setRelFilter] = useState("");

  const grouped = useMemo(() => {
    const out = new Map<string, Observation[]>();
    for (const o of detail.data?.observations ?? []) {
      if (!out.has(o.kind)) out.set(o.kind, []);
      out.get(o.kind)!.push(o);
    }
    return [...out.entries()];
  }, [detail.data]);

  // Collapse repeated relationships (same type and entity seen in several runs).
  const relationships = useMemo(() => {
    const seen = new Map<string, NonNullable<typeof detail.data>["relationships"][number] & { count: number; origins: Set<string> }>();
    for (const r of detail.data?.relationships ?? []) {
      const key = `${r.direction}|${r.type}|${r.other_id}`;
      const existing = seen.get(key);
      if (existing) { existing.count++; existing.origins.add(r.origin); existing.confidence = Math.max(existing.confidence, r.confidence); }
      else seen.set(key, { ...r, count: 1, origins: new Set([r.origin]) });
    }
    const f = relFilter.toLowerCase();
    return [...seen.values()].filter((r) => !f || `${r.type} ${r.other_value} ${r.other_type}`.toLowerCase().includes(f));
  }, [detail.data, relFilter]);

  if (detail.error) return <div className="p-4"><ErrorBanner message={detail.error} onRetry={detail.reload} /></div>;
  if (!detail.data) return <div className="p-4 text-muted"><Spinner /> Loading entity</div>;
  const e = detail.data;
  const attributes = Object.entries(e.attributes).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && !v.length));

  return (
    <div className={compact ? "space-y-4 p-4" : "space-y-5 p-5"}>
      <header>
        <TypeBadge type={e.type} />
        <div className="mt-1 flex items-start gap-2">
          <h2 className="mono break-all text-[15px] font-semibold">{e.value}</h2>
          <button className="mt-1 text-xxs text-muted underline hover:text-fg" aria-label="Copy value"
            onClick={() => { navigator.clipboard.writeText(e.value); toast("Copied"); }}>
            copy
          </button>
        </div>
        <div className="text-xxs text-muted">First seen {formatTime(e.first_seen)} · last seen {formatTime(e.last_seen)}</div>
      </header>

      {attributes.length > 0 && (
        <section>
          <h3 className="label mb-1.5">Attributes</h3>
          <dl className="grid grid-cols-[minmax(90px,140px)_1fr] gap-x-3 gap-y-1">
            {attributes.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted">{humanize(k)}</dt>
                <dd className="mono break-all">{typeof v === "string" && /^https:\/\//.test(v)
                  ? <a href={v} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">{v}</a>
                  : formatValue(v)}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      <section>
        <h3 className="label mb-1.5">Observations ({e.observations.length})</h3>
        {grouped.length === 0 && <p className="text-muted">No source reported facts about this entity directly; it appears through relationships.</p>}
        <div className="space-y-2">
          {grouped.map(([kind, items]) => (
            <ObservationGroup key={kind} kind={kind} items={items} onEvidence={setEvidence} />
          ))}
        </div>
      </section>

      <section>
        <div className="mb-1.5 flex items-center justify-between gap-2">
          <h3 className="label">Relationships ({relationships.length})</h3>
          {(e.relationships.length > 8) && (
            <input className="input max-w-[200px] py-1 text-xs" placeholder="Filter" value={relFilter}
              onChange={(ev) => setRelFilter(ev.target.value)} aria-label="Filter relationships" />
          )}
        </div>
        <ul className="divide-y divide-line/60 rounded border border-line">
          {relationships.length === 0 && <li className="px-3 py-2 text-muted">None</li>}
          {relationships.slice(0, 300).map((r) => (
            <li key={`${r.direction}-${r.type}-${r.other_id}`} className="flex items-center gap-2 px-3 py-1.5">
              <span className="w-4 text-center text-muted" title={r.direction === "out" ? "outgoing" : "incoming"}>{r.direction === "out" ? "→" : "←"}</span>
              <span className="w-40 shrink-0 text-muted">{humanize(r.type)}</span>
              <TypeBadge type={r.other_type} />
              <button className="mono min-w-0 flex-1 truncate text-left hover:text-accent" onClick={() => onSelectEntity(r.other_id)} title={r.other_value}>
                {r.other_value}
              </button>
              <span className="hidden text-xxs text-muted sm:inline">{[...r.origins].join(", ")}{r.count > 1 ? ` ×${r.count}` : ""}</span>
              <Confidence value={r.confidence} />
              {r.evidence_id && (
                <button className="text-xxs text-accent hover:underline" onClick={() => setEvidence(r.evidence_id)}>evidence</button>
              )}
            </li>
          ))}
          {relationships.length > 300 && <li className="px-3 py-2 text-muted">{relationships.length - 300} more; use the filter.</li>}
        </ul>
      </section>

      {evidence && <EvidenceViewer investigationId={investigationId} evidenceId={evidence} onClose={() => setEvidence(null)} />}
    </div>
  );
}

function ObservationGroup({ kind, items, onEvidence }: { kind: string; items: Observation[]; onEvidence: (id: string) => void }) {
  const [open, setOpen] = useState(items.length <= 6);
  const shown = open ? items : items.slice(0, 6);
  return (
    <div className="rounded border border-line">
      <div className="flex items-center justify-between border-b border-line/60 bg-raised/50 px-3 py-1">
        <span className="mono font-medium">{kind}</span>
        <span className="text-xxs text-muted">{items.length}</span>
      </div>
      <ul className="divide-y divide-line/40">
        {shown.map((o) => (
          <li key={o.id} className="grid grid-cols-[1fr_auto] gap-x-3 px-3 py-1.5">
            <div className="mono min-w-0 break-words"><ValueView value={o.value} /></div>
            <div className="flex items-center gap-2 text-xxs text-muted">
              <Confidence value={o.confidence} />
            </div>
            <div className="col-span-2 mt-0.5 flex flex-wrap gap-x-3 text-xxs text-muted">
              <span title={o.method}>{o.source}</span>
              <span>{formatTime(o.collected_at)}</span>
              {o.source_url && <a href={o.source_url} target="_blank" rel="noreferrer noopener" className="hover:text-accent">source</a>}
              {o.evidence_id && <button className="text-accent hover:underline" onClick={() => onEvidence(o.evidence_id!)}>evidence {o.evidence_id.slice(0, 10)}</button>}
            </div>
          </li>
        ))}
      </ul>
      {items.length > 6 && (
        <button className="w-full border-t border-line/60 py-1 text-xxs text-accent hover:bg-raised/50" onClick={() => setOpen(!open)}>
          {open ? "Show fewer" : `Show all ${items.length}`}
        </button>
      )}
    </div>
  );
}

/** Lists of records (archive captures, passive DNS rows) as short lists
 * instead of one long run-on string. */
function ValueView({ value }: { value: unknown }) {
  const [all, setAll] = useState(false);
  if (Array.isArray(value) && value.some((v) => v !== null && typeof v === "object")) {
    const shown = all ? value : value.slice(0, 5);
    return (
      <ul className="space-y-0.5">
        {shown.map((v, i) => <li key={i} className="break-all">{formatValue(v)}</li>)}
        {value.length > 5 && (
          <li><button className="text-xxs text-accent hover:underline" onClick={() => setAll(!all)}>
            {all ? "show fewer" : `+${value.length - 5} more`}
          </button></li>
        )}
      </ul>
    );
  }
  return <>{formatValue(value)}</>;
}

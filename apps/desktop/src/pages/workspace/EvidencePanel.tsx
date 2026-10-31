import { useMemo, useState } from "react";
import { api } from "../../api";
import { EvidenceViewer } from "../../components/EvidenceViewer";
import { EmptyState, ErrorBanner, Spinner } from "../../components/ui";
import { formatBytes, formatTime, useLoad } from "../../lib";
import type { PanelProps } from "../Workspace";

export function EvidencePanel({ inv }: PanelProps) {
  const list = useLoad(() => api.evidenceList(inv.id), [inv.id, inv.updated_at]);
  const [filter, setFilter] = useState("");
  const [collector, setCollector] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const collectors = useMemo(() => [...new Set((list.data ?? []).map((e) => e.collector))].sort(), [list.data]);
  const rows = useMemo(() => {
    const f = filter.toLowerCase();
    return (list.data ?? []).filter((e) => (!collector || e.collector === collector)
      && (!f || `${e.locator} ${e.id}`.toLowerCase().includes(f)));
  }, [list.data, filter, collector]);

  if (list.error) return <div className="p-6"><ErrorBanner message={list.error} onRetry={list.reload} /></div>;
  if (!list.data) return <div className="p-6 text-muted"><Spinner /> Loading evidence</div>;
  if (list.data.length === 0) return <EmptyState title="No evidence stored">Raw responses from collectors are kept here so every observation can be checked.</EmptyState>;

  return (
    <div className="flex h-full flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
        <input className="input max-w-sm" placeholder="Filter by request or SHA-256" value={filter}
          onChange={(e) => setFilter(e.target.value)} aria-label="Filter evidence" />
        <select className="input w-44" value={collector} onChange={(e) => setCollector(e.target.value)} aria-label="Collector">
          <option value="">All collectors</option>
          {collectors.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <span className="text-muted">{rows.length} of {list.data.length} items · stored verbatim, identified by SHA-256 of the content</span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="tbl">
          <thead><tr><th>Collector</th><th>Request</th><th>Collected</th><th className="text-right">Size</th><th>SHA-256</th></tr></thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id} className="cursor-pointer hover:bg-raised/60" onClick={() => setOpen(e.id)}>
                <td className="mono">{e.collector}</td>
                <td className="mono max-w-0 truncate" title={e.locator}>
                  <button className="max-w-full truncate text-left hover:text-accent" onClick={() => setOpen(e.id)}>{e.locator}</button>
                </td>
                <td className="whitespace-nowrap text-muted">{formatTime(e.collected_at)}</td>
                <td className="text-right tabular-nums text-muted">{formatBytes(e.size)}</td>
                <td className="mono text-muted">{e.id.slice(0, 16)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {open && <EvidenceViewer investigationId={inv.id} evidenceId={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

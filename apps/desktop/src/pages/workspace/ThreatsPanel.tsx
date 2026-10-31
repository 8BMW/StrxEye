import { useMemo, useState } from "react";
import { api } from "../../api";
import { EvidenceViewer } from "../../components/EvidenceViewer";
import { EmptyState, ErrorBanner, Spinner, TypeBadge } from "../../components/ui";
import { formatTime, href, useLoad } from "../../lib";
import type { PanelProps } from "../Workspace";

const SEVERITIES = ["high", "medium", "low", "info"] as const;
const SEVERITY_STYLE: Record<string, string> = {
  high: "border-bad/50 bg-bad/10 text-bad",
  medium: "border-warn/50 bg-warn/10 text-warn",
  low: "border-accent/40 bg-accent/10 text-accent",
  info: "border-line bg-raised text-muted",
};

export function ThreatsPanel({ inv, route }: PanelProps) {
  const rows = useLoad(() => api.threats(inv.id), [inv.id, inv.updated_at]);
  const [severity, setSeverity] = useState<string>("");
  const [evidence, setEvidence] = useState<string | null>(null);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const r of rows.data ?? []) c[r.severity] = (c[r.severity] ?? 0) + 1;
    return c;
  }, [rows.data]);
  const shown = (rows.data ?? []).filter((r) => !severity || r.severity === severity);

  if (rows.error) return <div className="p-6"><ErrorBanner message={rows.error} onRetry={rows.reload} /></div>;
  if (!rows.data) return <div className="p-6 text-muted"><Spinner /> Checking threat signals</div>;
  if (rows.data.length === 0) {
    return (
      <EmptyState title="No threat signals"
        action={<a className="btn" href={href({ ...route, tab: "collect", entity: undefined })}>Collect more</a>}>
        None of the collected entities appear on the block lists, in OTX reports or in VirusTotal
        detections that were checked. Expand domains to their IPs so they are checked too.
      </EmptyState>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="grid grid-cols-2 gap-3 border-b border-line p-4 lg:grid-cols-4">
        {SEVERITIES.map((s) => (
          <button key={s} onClick={() => setSeverity(severity === s ? "" : s)} aria-pressed={severity === s}
            className={`rounded-md border px-4 py-3 text-left transition-colors ${SEVERITY_STYLE[s]} ${severity && severity !== s ? "opacity-40" : ""}`}>
            <div className="text-xxs font-semibold uppercase tracking-wider">{s}</div>
            <div className="text-2xl font-semibold tabular-nums">{counts[s] ?? 0}</div>
          </button>
        ))}
      </div>
      <p className="border-b border-line px-4 py-2 text-xxs text-muted">
        Severity follows fixed rules per source (block-list category, number of VirusTotal detections,
        OTX mentions, unverified CVE guesses). It is not a combined risk score; check the evidence for each row.
      </p>
      <div className="min-h-0 flex-1 overflow-auto">
        <table className="tbl">
          <thead><tr><th>Severity</th><th>Entity</th><th>Category</th><th>Signal</th><th>Source</th><th>Collected</th><th /></tr></thead>
          <tbody>
            {shown.map((r, i) => (
              <tr key={i} className="hover:bg-raised/60">
                <td><span className={`chip ${SEVERITY_STYLE[r.severity]}`}>{r.severity}</span></td>
                <td>
                  <div className="flex items-center gap-2">
                    <TypeBadge type={r.entity_type} />
                    <a className="mono hover:text-accent" href={href({ ...route, tab: "entities", entity: r.entity_id })}>{r.entity}</a>
                  </div>
                </td>
                <td className="text-muted">{r.category}</td>
                <td>{r.summary}</td>
                <td className="mono text-muted">{r.source}</td>
                <td className="whitespace-nowrap text-muted">{formatTime(r.collected_at)}</td>
                <td>{r.evidence_id && <button className="text-xxs text-accent hover:underline" onClick={() => setEvidence(r.evidence_id)}>evidence</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {evidence && <EvidenceViewer investigationId={inv.id} evidenceId={evidence} onClose={() => setEvidence(null)} />}
    </div>
  );
}

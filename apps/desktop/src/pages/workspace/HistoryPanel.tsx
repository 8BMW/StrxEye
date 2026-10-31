import { useEffect, useMemo, useState } from "react";
import { api } from "../../api";
import { EmptyState, ErrorBanner, Spinner } from "../../components/ui";
import { formatTime, formatValue } from "../../lib";
import type { Diff, DiffFact } from "../../types";
import type { PanelProps } from "../Workspace";

export function HistoryPanel({ inv }: PanelProps) {
  const runs = useMemo(() => inv.runs.filter((r) => r.status !== "running"), [inv.runs]);
  const targets = useMemo(() => [...new Set(runs.map((r) => r.target_value))], [runs]);
  const comparable = targets.filter((t) => runs.filter((r) => r.target_value === t).length >= 2);
  const [target, setTarget] = useState(comparable[0] ?? "");
  const forTarget = runs.filter((r) => r.target_value === target);
  const [older, setOlder] = useState("");
  const [newer, setNewer] = useState("");
  const [diff, setDiff] = useState<Diff | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    // Runs are listed newest first: default to comparing the latest two.
    setNewer(forTarget[0]?.id ?? "");
    setOlder(forTarget[1]?.id ?? "");
    setDiff(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);

  if (comparable.length === 0) {
    return (
      <EmptyState title="Nothing to compare yet">
        Comparison needs at least two completed runs on the same target. Run collection on a target again later
        to see what appeared or disappeared.
      </EmptyState>
    );
  }

  const compare = async () => {
    setBusy(true);
    setError(null);
    try { setDiff(await api.diff(inv.id, older, newer)); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <div className="h-full overflow-auto p-5">
      <div className="flex flex-wrap items-end gap-3">
        <label className="space-y-1"><span className="label block">Target</span>
          <select className="input w-56" value={target} onChange={(e) => setTarget(e.target.value)}>
            {comparable.map((t) => <option key={t}>{t}</option>)}
          </select></label>
        <label className="space-y-1"><span className="label block">Older run</span>
          <select className="input w-72" value={older} onChange={(e) => setOlder(e.target.value)}>
            {forTarget.map((r) => <option key={r.id} value={r.id}>{r.id} · {formatTime(r.started_at)}</option>)}
          </select></label>
        <label className="space-y-1"><span className="label block">Newer run</span>
          <select className="input w-72" value={newer} onChange={(e) => setNewer(e.target.value)}>
            {forTarget.map((r) => <option key={r.id} value={r.id}>{r.id} · {formatTime(r.started_at)}</option>)}
          </select></label>
        <button className="btn-primary" onClick={compare} disabled={busy || !older || !newer || older === newer}>
          {busy ? <Spinner /> : null} Compare
        </button>
      </div>
      {error && <div className="mt-4"><ErrorBanner message={error} /></div>}
      {diff && (
        <div className="mt-5 space-y-4">
          <p className="text-muted">
            {diff.added.length} added · {diff.removed.length} removed · {diff.unchanged} unchanged.
            Compared collectors: {diff.compared_collectors.join(", ") || "none"}.
          </p>
          {diff.not_compared.length > 0 && (
            <p className="text-warn">Not compared because they failed or did not run in one of the two runs: {diff.not_compared.join(", ")}.
              Their data is left out so failures do not show up as removals.</p>
          )}
          <DiffList title="Appeared" tone="text-ok" sign="+" facts={diff.added} />
          <DiffList title="Disappeared" tone="text-bad" sign="−" facts={diff.removed} />
        </div>
      )}
    </div>
  );
}

function DiffList({ title, tone, sign, facts }: { title: string; tone: string; sign: string; facts: DiffFact[] }) {
  if (!facts.length) return null;
  return (
    <section className="card overflow-hidden">
      <h3 className={`border-b border-line px-3 py-2 font-semibold ${tone}`}>{title} ({facts.length})</h3>
      <table className="tbl">
        <thead><tr><th /><th>Entity</th><th>Kind</th><th>Value</th><th>Source</th></tr></thead>
        <tbody>
          {facts.map((f, i) => (
            <tr key={i}>
              <td className={`mono ${tone}`}>{sign}</td>
              <td className="mono">{f.entity}</td>
              <td className="mono text-muted">{f.kind}</td>
              <td className="mono break-all">{formatValue(f.value)}</td>
              <td className="text-muted">{f.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

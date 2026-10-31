import { useState } from "react";
import { useApp } from "../App";
import { api } from "../api";
import { formatTime, useLoad } from "../lib";
import { ErrorBanner, Icon, useToast } from "./ui";

const INTERVALS = [["6h", "every 6 hours"], ["12h", "every 12 hours"], ["24h", "daily"], ["7d", "weekly"]];

/** Watches for one investigation: add, pause, remove. */
export function MonitorCard({ investigationId, suggestedTarget }: { investigationId: string; suggestedTarget: string }) {
  const toast = useToast();
  const { refreshAlerts } = useApp();
  const [running, setRunning] = useState<number | null>(null);
  const watches = useLoad(() => api.watches(investigationId), [investigationId]);
  const [target, setTarget] = useState("");
  const [every, setEvery] = useState("24h");
  const [error, setError] = useState<string | null>(null);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await api.addWatch(investigationId, { target: target || suggestedTarget, every, direct: false, expand: true });
      setTarget("");
      watches.reload();
      toast("Watching target. The first run starts within a minute.");
    } catch (err) { setError((err as Error).message); }
  };

  return (
    <section className="card p-4">
      <div className="mb-2 flex items-center gap-2">
        <Icon name="eye" />
        <h2 className="font-semibold">Monitoring</h2>
      </div>
      <p className="mb-3 text-xxs text-muted">Re-collect a target on a schedule and get an alert when something changes: new IPs,
        nameservers, subdomains, certificates, or a new listing in a threat feed.</p>
      <form className="flex flex-wrap gap-2" onSubmit={add}>
        <input className="input mono min-w-[200px] flex-1" placeholder={suggestedTarget || "example.com"} value={target}
          onChange={(e) => setTarget(e.target.value)} aria-label="Target to watch" />
        <select className="input w-40" value={every} onChange={(e) => setEvery(e.target.value)} aria-label="Interval">
          {INTERVALS.map(([v, label]) => <option key={v} value={v}>{label}</option>)}
        </select>
        <button className="btn" disabled={!target && !suggestedTarget}>Watch</button>
      </form>
      {error && <div className="mt-2"><ErrorBanner message={error} /></div>}
      {watches.data && watches.data.length > 0 && (
        <ul className="mt-3 divide-y divide-line/60 rounded border border-line">
          {watches.data.map((w) => (
            <li key={w.id} className="flex flex-wrap items-center gap-2 px-3 py-2">
              <span className="mono">{w.target_value}</span>
              <span className="text-xxs text-muted">every {w.interval_hours}h · next {formatTime(w.next_run_at)}</span>
              {w.last_error && <span className="text-xxs text-warn">{w.last_error}</span>}
              <span className="ml-auto flex gap-1">
                <button className="btn btn-sm" disabled={running !== null} onClick={async () => {
                  setRunning(w.id);
                  try {
                    const r = await api.runWatch(w.id);
                    toast(r.alerts ? `${r.alerts} change alert(s)` : r.error ? `Run finished: ${r.error}` : "Run finished: no changes");
                    refreshAlerts();
                  } catch (err) { toast((err as Error).message, "error"); }
                  finally { setRunning(null); watches.reload(); }
                }}>{running === w.id ? "Running…" : "Run now"}</button>
                <button className="btn btn-sm" onClick={async () => { await api.setWatchEnabled(w.id, !w.enabled); watches.reload(); }}>
                  {w.enabled ? "Pause" : "Resume"}
                </button>
                <button className="btn-danger btn-sm" onClick={async () => { await api.deleteWatch(w.id); watches.reload(); }}>Remove</button>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

import { useMemo, useState } from "react";
import { api } from "../api";
import { useApp } from "../App";
import { EmptyState, ErrorBanner, Icon, Spinner, useToast } from "../components/ui";
import { formatTime, href, relativeTime, useLoad } from "../lib";

const SEVERITY_STYLE: Record<string, string> = {
  high: "border-bad/50 bg-bad/10 text-bad",
  medium: "border-warn/50 bg-warn/10 text-warn",
  low: "border-accent/40 bg-accent/10 text-accent",
  info: "border-line bg-raised text-muted",
};

export function AlertsPage() {
  const { refreshAlerts } = useApp();
  const toast = useToast();
  const [showRead, setShowRead] = useState(false);
  const alerts = useLoad(() => api.alerts(!showRead), [showRead]);
  const watches = useLoad(() => api.watches(), []);
  const [busy, setBusy] = useState(false);

  const unread = useMemo(() => (alerts.data ?? []).filter((a) => !a.read_at), [alerts.data]);

  const markRead = async (ids?: number[]) => {
    await api.markAlertsRead(ids);
    alerts.reload();
    refreshAlerts();
  };

  const runNow = async () => {
    setBusy(true);
    try {
      const results = await api.runDueWatches();
      toast(results.length ? `Ran ${results.length} due watch(es)` : "No watches are due right now");
      alerts.reload();
      watches.reload();
      refreshAlerts();
    } catch (e) {
      toast((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-6 py-4">
        <div>
          <h1 className="text-lg font-semibold">Alerts</h1>
          <p className="max-w-3xl text-muted">
            Changes found when a watched target was collected again. Sources that failed in either run are left out
            of the comparison, so an outage is never reported as a change.
          </p>
        </div>
        <div className="flex gap-2">
          <label className="flex items-center gap-1.5">
            <input type="checkbox" className="accent-[rgb(var(--accent))]" checked={showRead}
              onChange={(e) => setShowRead(e.target.checked)} />
            Show read
          </label>
          <button className="btn" onClick={runNow} disabled={busy}>{busy ? <Spinner /> : <Icon name="refresh" size={14} />} Run due watches</button>
          <button className="btn" onClick={() => markRead()} disabled={!unread.length}>Mark all read</button>
        </div>
      </header>

      <div className="grid min-h-0 flex-1 grid-cols-1 overflow-auto xl:grid-cols-[1fr_380px]">
        <section className="min-w-0 p-6">
          {alerts.error && <ErrorBanner message={alerts.error} onRetry={alerts.reload} />}
          {!alerts.data && !alerts.error && <div className="text-muted"><Spinner /> Loading</div>}
          {alerts.data && alerts.data.length === 0 && (
            <EmptyState title={showRead ? "No alerts yet" : "No unread alerts"}>
              Watch a target from an investigation's Collect tab. STRX EYE re-collects it on schedule and alerts you
              when something changes.
            </EmptyState>
          )}
          <ul className="space-y-2">
            {alerts.data?.map((a) => (
              <li key={a.id} className={`card p-3 ${a.read_at ? "opacity-60" : ""}`}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`chip ${SEVERITY_STYLE[a.severity]}`}>{a.severity}</span>
                  <span className="font-medium">{a.title}</span>
                  <span className="ml-auto text-xxs text-muted" title={formatTime(a.created_at)}>{relativeTime(a.created_at)}</span>
                </div>
                {a.detail.summary && <div className="mono mt-1 break-all text-[12px]">{a.detail.summary}</div>}
                <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xxs text-muted">
                  <a className="hover:text-accent" href={href({ page: "investigation", id: a.investigation_id, tab: "history" })}>
                    {a.investigation}: compare runs
                  </a>
                  {a.detail.not_compared && a.detail.not_compared.length > 0 && (
                    <span>not compared: {a.detail.not_compared.join(", ")}</span>
                  )}
                  {!a.read_at && <button className="ml-auto text-accent hover:underline" onClick={() => markRead([a.id])}>mark read</button>}
                </div>
              </li>
            ))}
          </ul>
        </section>

        <aside className="border-t border-line p-6 xl:border-l xl:border-t-0">
          <h2 className="label mb-2">Watches</h2>
          {watches.data?.length === 0 && <p className="text-muted">No watched targets.</p>}
          <ul className="space-y-2">
            {watches.data?.map((w) => (
              <li key={w.id} className="card p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="mono truncate">{w.target_value}</span>
                  <span className="text-xxs text-muted">every {w.interval_hours}h{w.enabled ? "" : " · paused"}</span>
                </div>
                <div className="text-xxs text-muted">{w.investigation}</div>
                <div className="text-xxs text-muted">
                  next run {formatTime(w.next_run_at)}
                  {w.last_error && <span className="block text-warn">{w.last_error}</span>}
                </div>
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xxs text-muted">
            Watches run while STRX EYE is open. To keep monitoring with the app closed, schedule
            <span className="mono"> strxeye monitor run </span> with Task Scheduler or cron.
          </p>
        </aside>
      </div>
    </div>
  );
}

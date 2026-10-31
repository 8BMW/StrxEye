import { useMemo, useState } from "react";
import { api } from "../api";
import { EmptyState, ErrorBanner, Icon, Spinner } from "../components/ui";
import { formatTime, formatValue, useLoad } from "../lib";

export function AuditPage() {
  const log = useLoad(() => api.audit(), []);
  const [filter, setFilter] = useState("");
  const rows = useMemo(() => {
    const f = filter.toLowerCase();
    return (log.data ?? []).filter((r) => !f || `${r.action} ${r.investigation_id ?? ""} ${JSON.stringify(r.detail)}`.toLowerCase().includes(f));
  }, [log.data, filter]);

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-line px-6 py-4">
        <div>
          <h1 className="text-lg font-semibold">Audit log</h1>
          <p className="text-muted">Local record of sensitive operations: runs started, exports, deletions, setting and plugin changes.</p>
        </div>
        <button className="btn" onClick={log.reload}><Icon name="refresh" /> Refresh</button>
      </header>
      <div className="border-b border-line px-6 py-2">
        <input className="input max-w-sm" placeholder="Filter by action, investigation or detail" value={filter}
          onChange={(e) => setFilter(e.target.value)} aria-label="Filter audit log" />
      </div>
      <div className="flex-1 overflow-auto">
        {log.error && <div className="p-6"><ErrorBanner message={log.error} onRetry={log.reload} /></div>}
        {log.loading && !log.data && <div className="p-6 text-muted"><Spinner /> Loading</div>}
        {log.data && rows.length === 0 && <EmptyState title="Nothing logged yet" />}
        {rows.length > 0 && (
          <table className="tbl">
            <thead><tr><th>Time</th><th>Action</th><th>Investigation</th><th>Detail</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="whitespace-nowrap text-muted">{formatTime(r.at)}</td>
                  <td className="mono">{r.action}</td>
                  <td className="mono text-muted">{r.investigation_id ?? "—"}</td>
                  <td className="mono break-all">{formatValue(r.detail)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

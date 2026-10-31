import { useState } from "react";
import { api } from "../api";
import { useApp } from "../App";
import { ErrorBanner, Icon, Modal, Spinner, TypeBadge, useToast } from "../components/ui";
import { href, navigate, useLoad, WORKSPACE_TABS, type Route, type WorkspaceTab } from "../lib";
import type { Investigation } from "../types";
import { CollectPanel } from "./workspace/CollectPanel";
import { EntitiesPanel } from "./workspace/EntitiesPanel";
import { EvidencePanel } from "./workspace/EvidencePanel";
import { GraphPanel } from "./workspace/GraphPanel";
import { HistoryPanel } from "./workspace/HistoryPanel";
import { ReportPanel } from "./workspace/ReportPanel";
import { TimelinePanel } from "./workspace/TimelinePanel";

const TAB_LABELS: Record<WorkspaceTab, string> = {
  collect: "Collect",
  entities: "Entities",
  graph: "Graph",
  timeline: "Timeline",
  evidence: "Evidence",
  history: "History",
  report: "Report",
};

export interface PanelProps {
  inv: Investigation;
  route: Extract<Route, { page: "investigation" }>;
  reload: () => void;
}

export function Workspace({ route }: { route: Extract<Route, { page: "investigation" }> }) {
  const inv = useLoad(() => api.investigation(route.id), [route.id]);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);

  if (inv.error && !inv.data) {
    return <div className="p-6"><ErrorBanner message={inv.error} onRetry={inv.reload} /></div>;
  }
  if (!inv.data) return <div className="flex items-center gap-2 p-6 text-muted"><Spinner /> Loading investigation</div>;
  const data = inv.data;
  const total = Object.values(data.counts).reduce((a, b) => a + (b ?? 0), 0);

  const panelProps: PanelProps = { inv: data, route, reload: inv.reload };

  return (
    <div className="flex h-full flex-col">
      <header className="border-b border-line bg-panel px-6 pt-3">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-xxs text-muted">
              <a href={href({ page: "overview" })} className="hover:text-fg">Investigations</a>
              <Icon name="chevron" size={11} />
              <span className="mono">{data.id}</span>
            </div>
            <h1 className="truncate text-lg font-semibold">{data.name}</h1>
            {data.description && <p className="max-w-3xl truncate text-muted" title={data.description}>{data.description}</p>}
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
              <span className="text-xxs text-muted">Seeds:</span>
              {data.seeds.length === 0 && <span className="text-xxs text-muted">none yet</span>}
              {data.seeds.map((s) => (
                <span key={`${s.type}:${s.value}`} className="chip gap-1.5"><TypeBadge type={s.type} /><span className="mono">{s.value}</span></span>
              ))}
              <span className="ml-2 text-xxs text-muted">{total} entities · {data.runs.length} runs</span>
            </div>
          </div>
          <div className="flex shrink-0 gap-2">
            <button className="btn btn-sm" onClick={() => setEditing(true)}><Icon name="edit" size={14} /> Edit</button>
            <button className="btn-danger btn-sm" onClick={() => setDeleting(true)}><Icon name="trash" size={14} /> Delete</button>
          </div>
        </div>
        <nav className="mt-3 flex gap-1" role="tablist" aria-label="Investigation sections">
          {WORKSPACE_TABS.map((tab, i) => (
            <a key={tab} role="tab" aria-selected={route.tab === tab} href={href({ ...route, tab, entity: undefined })}
              title={`Alt+${i + 1}`}
              className={`border-b-2 px-3 py-2 ${route.tab === tab ? "border-accent text-fg" : "border-transparent text-muted hover:text-fg"}`}>
              {TAB_LABELS[tab]}
            </a>
          ))}
        </nav>
      </header>
      <div className="min-h-0 flex-1">
        {route.tab === "collect" && <CollectPanel {...panelProps} />}
        {route.tab === "entities" && <EntitiesPanel {...panelProps} />}
        {route.tab === "graph" && <GraphPanel {...panelProps} />}
        {route.tab === "timeline" && <TimelinePanel {...panelProps} />}
        {route.tab === "evidence" && <EvidencePanel {...panelProps} />}
        {route.tab === "history" && <HistoryPanel {...panelProps} />}
        {route.tab === "report" && <ReportPanel {...panelProps} />}
      </div>
      {editing && <EditDialog inv={data} onClose={() => setEditing(false)} onSaved={inv.reload} />}
      {deleting && <DeleteDialog inv={data} onClose={() => setDeleting(false)} />}
    </div>
  );
}

function EditDialog({ inv, onClose, onSaved }: { inv: Investigation; onClose: () => void; onSaved: () => void }) {
  const { reloadInvestigations } = useApp();
  const [name, setName] = useState(inv.name);
  const [description, setDescription] = useState(inv.description);
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal title="Edit investigation" onClose={onClose}>
      <form className="space-y-3" onSubmit={async (e) => {
        e.preventDefault();
        try {
          await api.updateInvestigation(inv.id, name, description);
          onSaved();
          reloadInvestigations();
          onClose();
        } catch (err) { setError((err as Error).message); }
      }}>
        <label className="block space-y-1"><span className="label">Name</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} required maxLength={200} /></label>
        <label className="block space-y-1"><span className="label">Scope and notes</span>
          <textarea className="input min-h-24" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={5000} /></label>
        {error && <ErrorBanner message={error} />}
        <div className="flex justify-end gap-2"><button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={!name.trim()}>Save</button></div>
      </form>
    </Modal>
  );
}

function DeleteDialog({ inv, onClose }: { inv: Investigation; onClose: () => void }) {
  const { reloadInvestigations } = useApp();
  const toast = useToast();
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <Modal title="Delete investigation" onClose={onClose}>
      <form className="space-y-3" onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        try {
          await api.deleteInvestigation(inv.id);
          reloadInvestigations();
          toast(`Deleted “${inv.name}”`);
          onClose();
          navigate({ page: "overview" });
        } catch (err) { toast((err as Error).message, "error"); setBusy(false); }
      }}>
        <p>This removes all runs, observations and stored evidence for <b>{inv.name}</b> from the local database
          and compacts the file. Copies held by backups or sync tools are not affected.</p>
        <label className="block space-y-1"><span className="label">Type the investigation ID ({inv.id}) to confirm</span>
          <input className="input mono" value={confirm} onChange={(e) => setConfirm(e.target.value)} /></label>
        <div className="flex justify-end gap-2"><button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn-danger" disabled={busy || confirm.trim() !== inv.id}>Delete permanently</button></div>
      </form>
    </Modal>
  );
}

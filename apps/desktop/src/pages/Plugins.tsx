import { useState } from "react";
import { api } from "../api";
import { useApp } from "../App";
import { EmptyState, ErrorBanner, Modal, Spinner, useToast } from "../components/ui";
import { useLoad } from "../lib";
import type { PluginInfo } from "../types";

export function PluginsPage() {
  const { reloadMeta } = useApp();
  const toast = useToast();
  const plugins = useLoad(() => api.plugins(), []);
  const [confirm, setConfirm] = useState<PluginInfo | null>(null);

  const untrust = async (p: PluginInfo) => {
    await api.untrustPlugin(p.name).catch((e) => toast(e.message, "error"));
    plugins.reload();
    reloadMeta();
    toast(`${p.name} will no longer run`);
  };

  return (
    <div className="h-full overflow-auto">
      <header className="border-b border-line px-6 py-4">
        <h1 className="text-lg font-semibold">Plugins</h1>
        <p className="max-w-3xl text-muted">
          Plugins add collectors. Installing a plugin package does not run it: STRX EYE only imports a plugin after you
          trust that exact version here or with <span className="mono">strxeye plugins trust</span>. An upgraded plugin
          has to be trusted again.
        </p>
      </header>
      <div className="max-w-4xl space-y-4 p-6">
        {plugins.error && <ErrorBanner message={plugins.error} onRetry={plugins.reload} />}
        {!plugins.data && !plugins.error && <div className="text-muted"><Spinner /> Loading</div>}
        {plugins.data?.length === 0 && (
          <div className="card">
            <EmptyState title="No plugins installed">
              Create one with <span className="mono">strxeye plugins new my_source</span>: it generates a working
              collector package with a passing test. Then <span className="mono">pip install -e</span> it and trust it here.
            </EmptyState>
          </div>
        )}
        {plugins.data?.map((p) => (
          <article key={p.name} className="card p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="font-semibold">{p.name}</h2>
                <div className="mono text-muted">{p.package} {p.version}</div>
                {p.summary && <p className="mt-1">{p.summary}</p>}
                <div className="mono mt-1 text-xxs text-muted">entry point {p.entry_point}</div>
                {p.homepage && <a className="text-xxs text-accent hover:underline" href={p.homepage} target="_blank" rel="noreferrer noopener">{p.homepage}</a>}
              </div>
              {p.trusted ? (
                <div className="flex items-center gap-2">
                  <span className="chip border-ok/50 text-ok">trusted</span>
                  <button className="btn-danger btn-sm" onClick={() => untrust(p)}>Stop trusting</button>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <span className="chip border-line text-muted">not trusted · not loaded</span>
                  <button className="btn btn-sm" onClick={() => setConfirm(p)}>Trust…</button>
                </div>
              )}
            </div>
          </article>
        ))}
        <section className="card p-4 text-muted">
          <h2 className="mb-1 font-semibold text-fg">Writing a plugin</h2>
          <p>A collector receives one target and returns observations, relationships and raw evidence. The SDK, the rules
            plugins must follow and a complete example are in <span className="mono">docs/plugins.md</span>.</p>
        </section>
      </div>
      {confirm && (
        <TrustDialog plugin={confirm} onClose={() => setConfirm(null)} onTrusted={() => {
          setConfirm(null);
          plugins.reload();
          reloadMeta();
          toast(`Trusted ${confirm.trust_key}`);
        }} />
      )}
    </div>
  );
}

function TrustDialog({ plugin, onClose, onTrusted }: { plugin: PluginInfo; onClose: () => void; onTrusted: () => void }) {
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal title={`Trust ${plugin.name}?`} onClose={onClose}>
      <form className="space-y-3" onSubmit={async (e) => {
        e.preventDefault();
        try {
          await api.trustPlugin(plugin.name, plugin.version);
          onTrusted();
        } catch (err) { setError((err as Error).message); }
      }}>
        <div className="rounded border border-warn/50 bg-warn/10 p-3 text-warn">
          A trusted plugin runs as Python code with your user account's permissions, including network and file
          access. Only trust plugins whose source you have read or whose author you trust.
        </div>
        <dl className="grid grid-cols-[100px_1fr] gap-y-1">
          <dt className="text-muted">Package</dt><dd className="mono">{plugin.package}</dd>
          <dt className="text-muted">Version</dt><dd className="mono">{plugin.version}</dd>
          <dt className="text-muted">Code</dt><dd className="mono break-all">{plugin.entry_point}</dd>
        </dl>
        <label className="block space-y-1">
          <span className="label">Type the plugin name ({plugin.name}) to confirm</span>
          <input className="input mono" value={typed} onChange={(e) => setTyped(e.target.value)} />
        </label>
        {error && <ErrorBanner message={error} />}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={typed.trim() !== plugin.name}>Trust {plugin.version}</button>
        </div>
      </form>
    </Modal>
  );
}

import { useState } from "react";
import { api } from "../../api";
import { ErrorBanner, Icon, Spinner, useToast } from "../../components/ui";
import { downloadText } from "../../lib";
import type { PanelProps } from "../Workspace";

const FORMATS = [
  { id: "html", label: "HTML", mime: "text/html", help: "Readable report with summary, scope, methodology, findings, relationships, limitations and evidence index. Print it to PDF from a browser." },
  { id: "json", label: "JSON", mime: "application/json", help: "The same content as structured data, for scripts and other tools." },
  { id: "csv", label: "CSV", mime: "text/csv", help: "One row per observation with source, time, confidence and evidence ID." },
];

export function ReportPanel({ inv }: PanelProps) {
  const toast = useToast();
  const [preview, setPreview] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const download = async (fmt: (typeof FORMATS)[number]) => {
    setBusy(fmt.id);
    setError(null);
    try {
      const text = await api.reportText(inv.id, fmt.id);
      downloadText(`strxeye-${inv.id}.${fmt.id}`, text, fmt.mime);
      toast(`${fmt.label} report downloaded`);
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(null); }
  };

  const showPreview = async () => {
    setBusy("preview");
    setError(null);
    try { setPreview(await api.reportText(inv.id, "html")); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(null); }
  };

  return (
    <div className="grid h-full grid-cols-1 lg:grid-cols-[340px_1fr]">
      <section className="space-y-3 border-b border-line p-5 lg:border-b-0 lg:border-r">
        <p className="text-muted">Reports label every item as an observation (from a named source), an inferred relationship, or a rule-based interpretation.</p>
        {FORMATS.map((f) => (
          <div key={f.id} className="card p-3">
            <div className="flex items-center justify-between">
              <span className="font-semibold">{f.label}</span>
              <button className="btn btn-sm" onClick={() => download(f)} disabled={busy !== null}>
                {busy === f.id ? <Spinner /> : <Icon name="download" size={14} />} Download
              </button>
            </div>
            <p className="mt-1 text-xxs text-muted">{f.help}</p>
          </div>
        ))}
        <button className="btn w-full justify-center" onClick={showPreview} disabled={busy !== null}>
          {busy === "preview" ? <Spinner /> : null} {preview ? "Refresh preview" : "Preview HTML report"}
        </button>
        <p className="text-xxs text-muted">PDF is not generated directly yet. Download the HTML report and use your browser's Print → Save as PDF; the report includes print styles.</p>
        {error && <ErrorBanner message={error} />}
      </section>
      <section className="min-h-0 bg-white">
        {preview ? (
          // Sandboxed without allow-scripts: nothing in the report can execute
          // (its own CSP also forbids scripts), so allow-same-origin only lets
          // the frame paint; a fully opaque srcdoc frame rendered blank in
          // testing. Never add allow-scripts here: report content comes from
          // remote sources.
          <iframe title="Report preview" sandbox="allow-same-origin" srcDoc={preview} className="h-full w-full border-0" />
        ) : (
          <div className="flex h-full items-center justify-center bg-bg text-muted">Preview appears here.</div>
        )}
      </section>
    </div>
  );
}

import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { downloadText, formatTime } from "../lib";
import type { EvidenceItem } from "../types";
import { ErrorBanner, Icon, Modal, Spinner, useToast } from "./ui";

export function EvidenceViewer({ investigationId, evidenceId, onClose }: {
  investigationId: string; evidenceId: string; onClose: () => void;
}) {
  const toast = useToast();
  const [item, setItem] = useState<EvidenceItem | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pretty, setPretty] = useState(true);

  useEffect(() => {
    api.evidence(investigationId, evidenceId).then(setItem).catch((e) => setError(e.message));
  }, [investigationId, evidenceId]);

  const isJson = item?.content_type.includes("json") ?? false;
  const shown = useMemo(() => {
    if (!item?.content) return "";
    if (isJson && pretty) {
      try { return JSON.stringify(JSON.parse(item.content), null, 2); } catch { return item.content; }
    }
    return item.content;
  }, [item, isJson, pretty]);

  return (
    <Modal title="Evidence" onClose={onClose} wide>
      {error && <ErrorBanner message={error} />}
      {!item && !error && <div className="text-muted"><Spinner /> Loading</div>}
      {item && (
        <div className="space-y-3">
          <dl className="grid grid-cols-[110px_1fr] gap-y-1">
            <dt className="text-muted">Collector</dt><dd className="mono">{item.collector}</dd>
            <dt className="text-muted">Request</dt><dd className="mono break-all">{item.locator}</dd>
            <dt className="text-muted">Collected</dt><dd>{formatTime(item.collected_at)}</dd>
            <dt className="text-muted">SHA-256</dt><dd className="mono break-all">{item.id}</dd>
            <dt className="text-muted">Size</dt><dd>{item.content?.length.toLocaleString()} characters</dd>
          </dl>
          <div className="flex gap-2">
            {isJson && <button className="btn btn-sm" onClick={() => setPretty(!pretty)}>{pretty ? "Show raw" : "Pretty-print"}</button>}
            <button className="btn btn-sm" onClick={() => { navigator.clipboard.writeText(item.content ?? ""); toast("Copied raw evidence"); }}>Copy</button>
            <button className="btn btn-sm" onClick={() => downloadText(`evidence-${item.id.slice(0, 12)}.${isJson ? "json" : "txt"}`, item.content ?? "", item.content_type)}>
              <Icon name="download" size={14} /> Download raw
            </button>
          </div>
          {/* Rendered as text only; evidence is never interpreted as HTML. */}
          <pre className="max-h-[50vh] overflow-auto rounded border border-line bg-bg p-3 font-mono text-[12px] leading-relaxed">{shown}</pre>
        </div>
      )}
    </Modal>
  );
}

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { STATUS_CLASS, TYPE_COLORS } from "../lib";
import type { EntityType } from "../types";

// Icons: small hand-drawn set (24px grid, stroke-based) to avoid an icon
// font or library for the dozen glyphs the app needs.
const PATHS: Record<string, string> = {
  overview: "M3 13h8V3H3zm10 8h8V11h-8zM3 21h8v-6H3zm10-18v6h8V3z",
  case: "M4 7h16v12H4zM9 7V5h6v2",
  collectors: "M4 6h16M4 12h16M4 18h10",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm7.4-3a7.4 7.4 0 0 0-.1-1.3l2-1.6-2-3.4-2.4 1a7.6 7.6 0 0 0-2.2-1.3L14.3 3h-4.6l-.4 2.4a7.6 7.6 0 0 0-2.2 1.3l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.6l-2 1.6 2 3.4 2.4-1c.7.6 1.4 1 2.2 1.3l.4 2.4h4.6l.4-2.4c.8-.3 1.5-.7 2.2-1.3l2.4 1 2-3.4-2-1.6c.1-.4.1-.9.1-1.3z",
  audit: "M9 5h10M9 12h10M9 19h10M4 5h.01M4 12h.01M4 19h.01",
  plus: "M12 5v14M5 12h14",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zm9 3-4.3-4.3",
  play: "M7 5v14l11-7z",
  stop: "M6 6h12v12H6z",
  close: "M6 6l12 12M18 6 6 18",
  download: "M12 4v11m0 0-4-4m4 4 4-4M5 20h14",
  trash: "M4 7h16M9 7V4h6v3m-8 0 1 13h8l1-13",
  edit: "M4 20h4L19 9l-4-4L4 16zM14 6l4 4",
  external: "M14 4h6v6m0-6-9 9M18 14v6H4V6h6",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
  fit: "M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5",
  chevron: "M9 6l6 6-6 6",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2m0 18v2M4.2 4.2l1.4 1.4m12.8 12.8 1.4 1.4M1 12h2m18 0h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  moon: "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z",
  command: "M9 6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3z",
  warning: "M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  bell: "M6 8a6 6 0 1 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.94 1.94 0 0 0 3.4 0",
  plug: "M9 2v6m6-6v6M6 8h12v4a6 6 0 0 1-12 0zm6 10v4",
  eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
};

export function Icon({ name, size = 16, className = "" }: { name: keyof typeof PATHS | string; size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d={PATHS[name] ?? ""} />
    </svg>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return (
    <span role="status" aria-label="Loading"
      className={`inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent ${className}`} />
  );
}

export function ErrorBanner({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-start gap-2 rounded border border-bad/40 bg-bad/10 px-3 py-2 text-bad">
      <Icon name="warning" className="mt-0.5 shrink-0" />
      <div className="flex-1">{message}</div>
      {onRetry && <button className="btn btn-sm" onClick={onRetry}>Retry</button>}
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="mx-auto flex max-w-md flex-col items-center gap-2 py-16 text-center">
      <div className="text-[15px] font-semibold">{title}</div>
      {children && <div className="text-muted">{children}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function TypeBadge({ type }: { type: EntityType | string }) {
  const color = TYPE_COLORS[type as EntityType] ?? "#94a3b8";
  return (
    <span className="chip gap-1 whitespace-nowrap" style={{ borderColor: `${color}66`, color }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {String(type).replace("_", " ")}
    </span>
  );
}

export function StatusText({ status }: { status: string }) {
  return <span className={`font-medium ${STATUS_CLASS[status] ?? ""}`}>{status.replace("_", " ")}</span>;
}

export function Confidence({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  return (
    <span className="inline-flex items-center gap-1.5" title={`Confidence ${pct}%`}>
      <span className="h-1 w-8 overflow-hidden rounded bg-line">
        <span className="block h-full bg-accent" style={{ width: `${pct}%` }} />
      </span>
      <span className="text-xxs text-muted">{pct}%</span>
    </span>
  );
}

export function Modal({ title, onClose, children, wide = false }: {
  title: string; onClose: () => void; children: ReactNode; wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    // Prefer the first form field; the header's close button comes earlier in
    // the DOM but should not take focus when the dialog opens.
    const body = ref.current;
    const first = body?.querySelector<HTMLElement>("input, textarea, select")
      ?? body?.querySelector<HTMLElement>(".overflow-auto button");
    first?.focus();
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); prev?.focus(); };
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 p-4 pt-[10vh]" onMouseDown={onClose}>
      <div ref={ref} role="dialog" aria-modal="true" aria-label={title} onMouseDown={(e) => e.stopPropagation()}
        className={`card flex max-h-[80vh] w-full flex-col shadow-2xl ${wide ? "max-w-4xl" : "max-w-lg"}`}>
        <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
          <h2 className="font-semibold">{title}</h2>
          <button className="text-muted hover:text-fg" onClick={onClose} aria-label="Close"><Icon name="close" /></button>
        </div>
        <div className="overflow-auto p-4">{children}</div>
      </div>
    </div>
  );
}

// Toasts -------------------------------------------------------------------

interface Toast { id: number; message: string; tone: "info" | "error" }
const ToastContext = createContext<(message: string, tone?: Toast["tone"]) => void>(() => {});
export const useToast = () => useContext(ToastContext);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((message: string, tone: Toast["tone"] = "info") => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, message, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), tone === "error" ? 8000 : 4000);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[60] flex flex-col gap-2" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`pointer-events-auto card max-w-sm px-3 py-2 shadow-lg ${t.tone === "error" ? "border-bad/50 text-bad" : ""}`}>
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="rounded border border-line bg-raised px-1 py-px font-mono text-xxs text-muted">{children}</kbd>;
}

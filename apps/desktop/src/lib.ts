import { useCallback, useEffect, useRef, useState } from "react";
import type { CollectionStatus, EntityType } from "./types";

// Routing ------------------------------------------------------------------
// Hash routes keep the app working from file://, a static server or a
// desktop webview without server-side rewrite rules.

export type Route =
  | { page: "overview" }
  | { page: "investigation"; id: string; tab: WorkspaceTab; entity?: number }
  | { page: "collectors" }
  | { page: "settings" }
  | { page: "audit" }
  | { page: "search"; q?: string };

export const WORKSPACE_TABS = ["collect", "entities", "graph", "timeline", "evidence", "history", "report"] as const;
export type WorkspaceTab = (typeof WORKSPACE_TABS)[number];

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  if (parts[0] === "inv" && parts[1]) {
    const tab = (WORKSPACE_TABS as readonly string[]).includes(parts[2]) ? (parts[2] as WorkspaceTab) : "collect";
    const entity = parts[3] ? Number(parts[3]) : undefined;
    return { page: "investigation", id: parts[1], tab, entity: Number.isFinite(entity) ? entity : undefined };
  }
  if (parts[0] === "collectors") return { page: "collectors" };
  if (parts[0] === "settings") return { page: "settings" };
  if (parts[0] === "audit") return { page: "audit" };
  if (parts[0] === "search") return { page: "search", q: parts[1] };
  return { page: "overview" };
}

export function href(route: Route): string {
  switch (route.page) {
    case "investigation":
      return `#/inv/${encodeURIComponent(route.id)}/${route.tab}${route.entity ? `/${route.entity}` : ""}`;
    case "overview":
      return "#/";
    case "search":
      return route.q ? `#/search/${encodeURIComponent(route.q)}` : "#/search";
    default:
      return `#/${route.page}`;
  }
}

export function navigate(route: Route) {
  window.location.hash = href(route);
}

export function useRoute(): Route {
  const [route, setRoute] = useState(() => parseRoute(window.location.hash));
  useEffect(() => {
    const onChange = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

// Data loading -------------------------------------------------------------

export interface Loaded<T> {
  data: T | undefined;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

/** Runs `load` when deps change; ignores responses from superseded calls. */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[]): Loaded<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const seq = useRef(0);
  useEffect(() => {
    const mine = ++seq.current;
    setLoading(true);
    load()
      .then((d) => { if (mine === seq.current) { setData(d); setError(null); } })
      .catch((e: Error) => { if (mine === seq.current) setError(e.message); })
      .finally(() => { if (mine === seq.current) setLoading(false); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, loading, reload };
}

// Formatting ---------------------------------------------------------------

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const seconds = (Date.now() - new Date(iso).getTime()) / 1000;
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}

export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(formatValue).join(", ");
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && v.length === 0))
      .map(([k, v]) => `${k}: ${formatValue(v)}`)
      .join("  ·  ");
  }
  return String(value);
}

export function formatBytes(n: number | undefined): string {
  if (n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export const TYPE_COLORS: Record<EntityType, string> = {
  domain: "#22c5e6",
  ip: "#3b82f6",
  network: "#6366f1",
  asn: "#a855f7",
  organization: "#f59e0b",
  certificate: "#10b981",
  url: "#14b8a6",
  technology: "#ec4899",
  hash: "#94a3b8",
  indicator: "#ef4444",
  malware: "#dc2626",
};

export const STATUS_CLASS: Record<CollectionStatus | string, string> = {
  ok: "text-ok",
  no_data: "text-muted",
  partial: "text-warn",
  error: "text-bad",
  timeout: "text-bad",
  cancelled: "text-warn",
  skipped: "text-muted",
  running: "text-accent",
  completed: "text-ok",
  failed: "text-bad",
  interrupted: "text-warn",
};

export function humanize(kind: string): string {
  return kind.replace(/_/g, " ");
}

/** Client-side guess of a target's type, mirroring strxeye/targets.py, used
 * only to pre-select collectors. The engine re-validates everything. */
export function guessTargetType(raw: string): EntityType | "asn" | null {
  const t = raw.trim();
  if (!t) return null;
  if (/^org:\s*\S/i.test(t)) return "organization";
  if (/^https?:\/\//i.test(t)) return "url";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t) || (t.includes(":") && /^[0-9a-f:.[\]]+$/i.test(t))) return "ip";
  if (/^as\d+$/i.test(t)) return "asn";
  if (/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(t)) return "hash";
  if (/^[^\s/]+\.[^\s/]+$/.test(t)) return "domain";
  return null;
}

export function downloadText(filename: string, text: string, type: string) {
  downloadBlob(filename, new Blob([text], { type }));
}

export function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

import type {
  Analytics, AuditEntry, Diff, EntityDetail, EntityRow, EvidenceItem, Graph, Investigation,
  InvestigationSummary, KeyStatus, Meta, PathResult, RunDetail, SearchResults, Settings,
  TimelineEvent, UpdateInfo,
} from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// Auth is either an HttpOnly cookie (browser, set by /auth) or a bearer
// header added by the dev proxy. A packaged shell can inject a token here.
declare global {
  interface Window { __STRXEYE_TOKEN__?: string }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (window.__STRXEYE_TOKEN__) headers.set("Authorization", `Bearer ${window.__STRXEYE_TOKEN__}`);
  let response: Response;
  try {
    response = await fetch(`/api${path}`, { ...init, headers, credentials: "same-origin" });
  } catch {
    throw new ApiError(0, "Cannot reach the STRX EYE engine. Is `strxeye serve` running?");
  }
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  const body = text ? safeJson(text) : null;
  if (!response.ok) {
    const detail = body && typeof body === "object" && "detail" in body ? body.detail : text;
    const message = typeof detail === "string" ? detail : JSON.stringify(detail);
    throw new ApiError(response.status, response.status === 401
      ? "Not authorised. Open the app through the link printed by `strxeye serve`."
      : message || `Request failed (HTTP ${response.status})`);
  }
  return body as T;
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

const q = (params: Record<string, string | number | boolean | undefined | null>) => {
  const s = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") s.set(k, String(v));
  const out = s.toString();
  return out ? `?${out}` : "";
};

const enc = encodeURIComponent;

export const api = {
  meta: () => request<Meta>("/meta"),
  audit: () => request<AuditEntry[]>("/audit"),
  changeSetting: (key: string, value: string) =>
    request<Settings>("/settings", { method: "PATCH", body: JSON.stringify({ key, value }) }),

  keys: () => request<KeyStatus[]>("/keys"),
  setKey: (name: string, value: string) =>
    request<void>(`/keys/${enc(name)}`, { method: "PUT", body: JSON.stringify({ value }) }),
  deleteKey: (name: string) => request<void>(`/keys/${enc(name)}`, { method: "DELETE" }),
  checkUpdate: (force = false) => request<UpdateInfo>(`/update${q({ force: force || undefined })}`),
  installUpdate: () => request<{ installing: string }>("/update/install", { method: "POST" }),
  search: (text: string, investigation?: string) =>
    request<SearchResults>(`/search${q({ q: text, investigation })}`),

  investigations: () => request<InvestigationSummary[]>("/investigations"),
  createInvestigation: (name: string, description: string) =>
    request<Investigation>("/investigations", { method: "POST", body: JSON.stringify({ name, description }) }),
  investigation: (id: string) => request<Investigation>(`/investigations/${enc(id)}`),
  updateInvestigation: (id: string, name: string, description: string) =>
    request<Investigation>(`/investigations/${enc(id)}`, {
      method: "PATCH", body: JSON.stringify({ name, description }),
    }),
  deleteInvestigation: (id: string) => request<void>(`/investigations/${enc(id)}`, { method: "DELETE" }),

  startRun: (id: string, body: { target: string; collectors?: string[]; direct: boolean; expand: boolean }) =>
    request<{ run_id: string }>(`/investigations/${enc(id)}/runs`, { method: "POST", body: JSON.stringify(body) }),
  run: (runId: string) => request<RunDetail>(`/runs/${enc(runId)}`),
  cancelRun: (runId: string) => request<{ cancelling: boolean }>(`/runs/${enc(runId)}/cancel`, { method: "POST" }),

  entities: (id: string, params: { type?: string; search?: string; limit?: number; offset?: number }) =>
    request<EntityRow[]>(`/investigations/${enc(id)}/entities${q(params)}`),
  entity: (id: string, entityId: number) => request<EntityDetail>(`/investigations/${enc(id)}/entities/${entityId}`),
  graph: (id: string, inferred: boolean) => request<Graph>(`/investigations/${enc(id)}/graph${q({ inferred })}`),
  analytics: (id: string) => request<Analytics>(`/investigations/${enc(id)}/analytics`),
  path: (id: string, source: number, target: number, inferred: boolean) =>
    request<PathResult>(`/investigations/${enc(id)}/path${q({ source, target, inferred })}`),
  timeline: (id: string) => request<TimelineEvent[]>(`/investigations/${enc(id)}/timeline`),
  evidenceList: (id: string) => request<EvidenceItem[]>(`/investigations/${enc(id)}/evidence`),
  evidence: (id: string, evidenceId: string) =>
    request<EvidenceItem>(`/investigations/${enc(id)}/evidence/${enc(evidenceId)}`),
  diff: (id: string, older: string, newer: string) =>
    request<Diff>(`/investigations/${enc(id)}/diff${q({ older, newer })}`),
  reportUrl: (id: string, format: string) => `/api/investigations/${enc(id)}/report${q({ format })}`,
  reportText: async (id: string, format: string): Promise<string> => {
    const headers = new Headers();
    if (window.__STRXEYE_TOKEN__) headers.set("Authorization", `Bearer ${window.__STRXEYE_TOKEN__}`);
    const r = await fetch(api.reportUrl(id, format), { headers, credentials: "same-origin" });
    if (!r.ok) throw new ApiError(r.status, `Report failed (HTTP ${r.status})`);
    return r.text();
  },
};

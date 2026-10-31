// Shapes returned by the local API (src/strxeye/server.py).

export type EntityType =
  | "domain" | "ip" | "network" | "asn" | "organization" | "certificate"
  | "url" | "technology" | "hash" | "indicator" | "malware";

export const ENTITY_TYPES: EntityType[] = [
  "domain", "ip", "network", "asn", "organization", "certificate", "url", "technology",
  "hash", "indicator", "malware",
];

export type CollectionStatus =
  | "ok" | "no_data" | "partial" | "error" | "timeout" | "skipped" | "cancelled";

export interface EntityRef { type: EntityType; value: string }

export interface InvestigationSummary {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
  entity_count: number;
  relationship_count: number;
  run_count: number;
  last_run_at: string | null;
  listed_count: number;
  type_counts: Partial<Record<EntityType, number>>;
}

export interface ThreatRow {
  entity_type: EntityType;
  entity: string;
  entity_id: number;
  category: string;
  severity: "high" | "medium" | "low" | "info";
  summary: string;
  source: string;
  confidence: number;
  collected_at: string;
  evidence_id: string | null;
}

export interface RunSummary {
  id: string;
  investigation_id: string;
  target_type: EntityType;
  target_value: string;
  options: { collectors: string[] | null; direct: boolean; expand: boolean };
  status: "running" | "completed" | "cancelled" | "failed" | "interrupted";
  started_at: string;
  finished_at: string | null;
  collector_count: number;
  failed_count: number;
  observation_count: number;
}

export interface CollectorRun {
  id: number;
  collector: string;
  target_type: EntityType;
  target_value: string;
  status: CollectionStatus;
  started_at: string;
  finished_at: string;
  error: string | null;
  notes: string[];
}

export interface RunDetail extends Omit<RunSummary, "collector_count" | "failed_count" | "observation_count"> {
  collectors: CollectorRun[];
  active: string[];
}

export interface Investigation {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
  seeds: EntityRef[];
  counts: Partial<Record<EntityType, number>>;
  runs: RunSummary[];
}

export interface EntityRow {
  id: number;
  type: EntityType;
  value: string;
  attributes: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
  observations: number;
  relationships: number;
}

export interface Observation {
  id: number;
  kind: string;
  value: unknown;
  source: string;
  method: string;
  source_url: string | null;
  confidence: number;
  evidence_id: string | null;
  collected_at: string;
  run_id: string;
}

export interface EntityRelationship {
  type: string;
  origin: string;
  confidence: number;
  evidence_id: string | null;
  collected_at: string;
  run_id: string;
  direction: "in" | "out";
  other_id: number;
  other_type: EntityType;
  other_value: string;
}

export interface EntityDetail extends Omit<EntityRow, "observations" | "relationships"> {
  observations: Observation[];
  relationships: EntityRelationship[];
}

export interface Provenance {
  origin: string;
  run_id: string;
  collected_at: string;
  confidence: number;
  evidence_id: string | null;
}

export interface GraphNode {
  id: number;
  type: EntityType;
  value: string;
  attributes: Record<string, unknown>;
  seed: boolean;
  first_seen: string;
  last_seen: string;
}

export interface GraphEdge {
  id: string;
  source: number;
  target: number;
  type: string;
  inferred: boolean;
  confidence: number;
  provenance?: Provenance[];
  explanation?: string;
}

export interface Graph {
  format: string;
  investigation: { id: string; name: string };
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface EvidenceItem {
  id: string;
  collector: string;
  locator: string;
  content_type: string;
  collected_at: string;
  size?: number;
  content?: string;
}

export interface CollectorInfo {
  name: string;
  title: string;
  description: string;
  version: string;
  accepts: EntityType[];
  sources: string[];
  direct: boolean;
  requires_key: string | null;
}

export interface Settings {
  network: { timeout: number; retries: number; user_agent: string };
  dns: { nameservers: string[] };
  collection: {
    allow_direct: boolean;
    collector_timeout: number;
    max_subdomains: number;
    max_certificates: number;
    max_expansions: number;
  };
  plugins: { trusted: string[] };
  updates: { check_on_start: boolean; repository: string };
}

export interface Meta {
  version: string;
  database: string;
  collectors: CollectorInfo[];
  settings: Settings;
  editable_settings: string[];
}

export interface DiffFact {
  entity_type: EntityType;
  entity: string;
  kind: string;
  value: unknown;
  source: string;
}

export interface Diff {
  older: { id: string; started_at: string; target: string };
  newer: { id: string; started_at: string; target: string };
  compared_collectors: string[];
  not_compared: string[];
  added: DiffFact[];
  removed: DiffFact[];
  unchanged: number;
}

export interface AuditEntry {
  id: number;
  at: string;
  action: string;
  investigation_id: string | null;
  detail: Record<string, unknown>;
}

export interface SearchHit {
  investigation_id: string;
  investigation: string;
  snippet: string;
}

export interface SearchResults {
  entities: (SearchHit & { id: number; type: EntityType; value: string })[];
  observations: (SearchHit & { id: number; kind: string; source: string; collected_at: string;
    entity_id: number; entity_type: EntityType; entity_value: string })[];
  evidence: (SearchHit & { id: string; collector: string; locator: string; collected_at: string })[];
}

export interface TimelineEvent {
  at: string;
  event: string;
  entity: string;
  entity_type: EntityType;
  source: string;
  observation_id: number | null;
  evidence_id: string | null;
  detail: string | null;
}

export interface Analytics {
  communities: { id: number; size: number; hub: string; types: Record<string, number> }[];
  isolated: number;
  most_connected: { id: number; type: EntityType; value: string; degree: number }[];
  membership: Record<string, number>;
}

export interface PathResult { nodes: number[]; edges: string[]; length: number }

export interface KeyStatus { name: string; description: string; source: string | null }

export interface UpdateInfo {
  current: string;
  latest: string;
  newer: boolean;
  release_url: string;
  notes: string;
  installer_name: string | null;
  can_self_install: boolean;
}

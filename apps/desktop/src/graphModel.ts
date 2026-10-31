import type { EntityType, Graph, GraphEdge, GraphNode } from "./types";

export interface ViewOptions {
  hiddenTypes: Set<EntityType>;
  showInferred: boolean;
  /** Nodes whose leaf neighbours are folded into them. */
  collapsed: Set<number>;
}

export interface ViewNode extends GraphNode {
  label: string;
  folded: number; // how many leaf neighbours are hidden inside this node
  degree: number;
}

export interface View {
  nodes: ViewNode[];
  edges: GraphEdge[];
  hiddenByType: number;
  hiddenByCollapse: number;
}

export function shortLabel(node: Pick<GraphNode, "type" | "value" | "attributes">): string {
  if (node.type === "certificate") {
    if (node.value.startsWith("sha256:")) return `cert ${node.value.slice(7, 19)}…`;
    const cn = node.attributes.common_name;
    return typeof cn === "string" ? `cert ${cn}` : node.value;
  }
  if (node.type === "asn" && typeof node.attributes.name === "string") {
    return `${node.value} ${(node.attributes.name as string).split(/[ ,]/)[0]}`;
  }
  return node.value.length > 42 ? `${node.value.slice(0, 40)}…` : node.value;
}

/** Applies type filters, the inferred toggle and collapsed nodes. Pure, so
 * the graph view and tests share one definition of what is visible. */
export function buildView(graph: Graph, opts: ViewOptions): View {
  const byType = graph.nodes.filter((n) => !opts.hiddenTypes.has(n.type));
  const typeVisible = new Set(byType.map((n) => n.id));
  const edges = graph.edges.filter((e) =>
    (opts.showInferred || !e.inferred) && typeVisible.has(e.source) && typeVisible.has(e.target));

  const neighbours = new Map<number, Set<number>>();
  for (const e of edges) {
    if (!neighbours.has(e.source)) neighbours.set(e.source, new Set());
    if (!neighbours.has(e.target)) neighbours.set(e.target, new Set());
    neighbours.get(e.source)!.add(e.target);
    neighbours.get(e.target)!.add(e.source);
  }

  const seeds = new Set(graph.nodes.filter((n) => n.seed).map((n) => n.id));
  const folded = new Map<number, number>();
  const hidden = new Set<number>();
  for (const parent of opts.collapsed) {
    if (!typeVisible.has(parent)) continue;
    let count = 0;
    for (const n of neighbours.get(parent) ?? []) {
      const links = neighbours.get(n)!;
      // A leaf only connects to the collapsed node. Seeds always stay.
      if (links.size === 1 && !seeds.has(n) && !opts.collapsed.has(n)) {
        hidden.add(n);
        count++;
      }
    }
    folded.set(parent, count);
  }

  const nodes: ViewNode[] = byType
    .filter((n) => !hidden.has(n.id))
    .map((n) => ({ ...n, label: shortLabel(n), folded: folded.get(n.id) ?? 0, degree: neighbours.get(n.id)?.size ?? 0 }));
  return {
    nodes,
    edges: edges.filter((e) => !hidden.has(e.source) && !hidden.has(e.target)),
    hiddenByType: graph.nodes.length - byType.length,
    hiddenByCollapse: hidden.size,
  };
}

export function searchNodes(nodes: GraphNode[], query: string): number[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return nodes.filter((n) => n.value.toLowerCase().includes(q)).map((n) => n.id);
}

/** Types hidden by default so very large graphs stay readable. */
export function defaultHiddenTypes(graph: Graph): Set<EntityType> {
  return graph.nodes.length > 300 ? new Set<EntityType>(["certificate"]) : new Set();
}

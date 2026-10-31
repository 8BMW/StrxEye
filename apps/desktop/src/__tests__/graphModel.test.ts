import { describe, expect, it } from "vitest";
import { buildView, defaultHiddenTypes, searchNodes, shortLabel } from "../graphModel";
import type { Graph, GraphNode } from "../types";

function node(id: number, type: GraphNode["type"], value: string, seed = false): GraphNode {
  return { id, type, value, seed, attributes: {}, first_seen: "", last_seen: "" };
}

// example.com -> 2 IPs -> network -> org, plus a CT certificate leaf and an
// inferred link to other.org.
const graph: Graph = {
  format: "strxeye-graph",
  investigation: { id: "x", name: "x" },
  nodes: [
    node(1, "domain", "example.com", true),
    node(2, "ip", "192.0.2.1"),
    node(3, "ip", "192.0.2.2"),
    node(4, "network", "192.0.2.0/24"),
    node(5, "certificate", "crtsh:9"),
    node(6, "domain", "other.org"),
  ],
  edges: [
    { id: "e1", source: 1, target: 2, type: "resolves_to", inferred: false, confidence: 1 },
    { id: "e2", source: 1, target: 3, type: "resolves_to", inferred: false, confidence: 1 },
    { id: "e3", source: 2, target: 4, type: "belongs_to_network", inferred: false, confidence: 1 },
    { id: "e4", source: 5, target: 1, type: "certificate_issued_for", inferred: false, confidence: 1 },
    { id: "i0", source: 1, target: 6, type: "shares_infrastructure", inferred: true, confidence: 0.4 },
  ],
};

const base = { hiddenTypes: new Set<GraphNode["type"]>(), showInferred: true, collapsed: new Set<number>() };

describe("buildView", () => {
  it("shows everything by default", () => {
    const v = buildView(graph, base);
    expect(v.nodes).toHaveLength(6);
    expect(v.edges).toHaveLength(5);
  });

  it("drops edges to hidden types", () => {
    const v = buildView(graph, { ...base, hiddenTypes: new Set(["certificate"]) });
    expect(v.nodes.map((n) => n.id)).not.toContain(5);
    expect(v.edges.map((e) => e.id)).not.toContain("e4");
    expect(v.hiddenByType).toBe(1);
  });

  it("can hide inferred relationships", () => {
    const v = buildView(graph, { ...base, showInferred: false });
    expect(v.edges.some((e) => e.inferred)).toBe(false);
  });

  it("folds only leaf neighbours into a collapsed node", () => {
    const v = buildView(graph, { ...base, collapsed: new Set([1]) });
    const ids = v.nodes.map((n) => n.id);
    // 3 (leaf IP), 5 (leaf cert) and 6 (leaf via inferred) fold; 2 has another link.
    expect(ids.sort()).toEqual([1, 2, 4]);
    expect(v.nodes.find((n) => n.id === 1)!.folded).toBe(3);
    expect(v.hiddenByCollapse).toBe(3);
  });

  it("hides nodes left without visible links, but never the seed", () => {
    const v = buildView(graph, { ...base, hiddenTypes: new Set(["ip"]), showInferred: false });
    // Network 4 only linked to IP 2, which is hidden; the seed stays.
    expect(v.nodes.map((n) => n.id).sort()).toEqual([1, 5]);
    expect(v.hiddenIsolated).toBe(2);
  });

  it("labels seeds, hubs and structural types", () => {
    const v = buildView(graph, base);
    const important = Object.fromEntries(v.nodes.map((n) => [n.id, n.important]));
    expect(important[1]).toBe(true); // seed
    expect(important[4]).toBe(true); // network
    expect(important[3]).toBe(false); // ordinary leaf IP
  });

  it("never folds seeds", () => {
    const v = buildView(graph, { ...base, collapsed: new Set([5]) });
    expect(v.nodes.map((n) => n.id)).toContain(1);
  });
});

describe("helpers", () => {
  it("searches case-insensitively", () => {
    expect(searchNodes(graph.nodes, "EXAMPLE")).toEqual([1]);
    expect(searchNodes(graph.nodes, "  ")).toEqual([]);
  });

  it("shortens certificate and long labels", () => {
    expect(shortLabel({ type: "certificate", value: "sha256:" + "a".repeat(64), attributes: {} })).toBe("cert aaaaaaaaaaaa…");
    expect(shortLabel({ type: "domain", value: "x".repeat(60), attributes: {} })).toHaveLength(41);
  });

  it("hides certificates on large graphs", () => {
    const big: Graph = { ...graph, nodes: Array.from({ length: 301 }, (_, i) => node(i, "domain", `d${i}.com`)) };
    expect(defaultHiddenTypes(big).has("certificate")).toBe(true);
    expect(defaultHiddenTypes(graph).size).toBe(0);
  });
});

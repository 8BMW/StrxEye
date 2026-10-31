import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import cytoscapeSvg from "cytoscape-svg";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../api";
import { EntityDetail } from "../../components/EntityDetail";
import { EvidenceViewer } from "../../components/EvidenceViewer";
import { Confidence, EmptyState, ErrorBanner, Icon, Spinner, TypeBadge } from "../../components/ui";
import { buildView, defaultHiddenTypes, searchNodes } from "../../graphModel";
import { downloadBlob, downloadText, formatTime, href, humanize, navigate, TYPE_COLORS, useLoad } from "../../lib";
import { ENTITY_TYPES, type Analytics, type EntityType, type Graph, type GraphEdge, type PathResult } from "../../types";

// Distinct colours for clusters, largest cluster first.
const CLUSTER_COLORS = ["#22c5e6", "#f59e0b", "#a855f7", "#10b981", "#ef4444", "#3b82f6",
  "#ec4899", "#84cc16", "#f97316", "#14b8a6"];
import type { PanelProps } from "../Workspace";

cytoscape.use(cytoscapeSvg);

type Selection = { kind: "node"; id: number } | { kind: "edge"; edge: GraphEdge } | null;

function themeColor(name: string): string {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v ? `rgb(${v.split(/\s+/).join(",")})` : "#888";
}

function useThemeVersion(): number {
  const [v, setV] = useState(0);
  useEffect(() => {
    const obs = new MutationObserver(() => setV((x) => x + 1));
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => obs.disconnect();
  }, []);
  return v;
}

export function GraphPanel({ inv, route }: PanelProps) {
  const graph = useLoad(() => api.graph(inv.id, true), [inv.id, inv.updated_at]);
  if (graph.error) return <div className="p-6"><ErrorBanner message={graph.error} onRetry={graph.reload} /></div>;
  if (!graph.data) return <div className="flex items-center gap-2 p-6 text-muted"><Spinner /> Building graph</div>;
  if (graph.data.nodes.length === 0) {
    return (
      <EmptyState title="Nothing to graph yet"
        action={<a className="btn-primary" href={href({ ...route, tab: "collect", entity: undefined })}>Start collecting</a>}>
        Entities and relationships appear here after a collection run.
      </EmptyState>
    );
  }
  return <GraphView graph={graph.data} investigationId={inv.id} />;
}

function GraphView({ graph, investigationId }: { graph: Graph; investigationId: string }) {
  const container = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const themeVersion = useThemeVersion();
  const [hiddenTypes, setHiddenTypes] = useState<Set<EntityType>>(() => defaultHiddenTypes(graph));
  const [showInferred, setShowInferred] = useState(true);
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set());
  const [query, setQuery] = useState("");
  const [selection, setSelection] = useState<Selection>(null);
  const [pathEnds, setPathEnds] = useState<{ from?: number; to?: number }>({});
  const [path, setPath] = useState<PathResult | null>(null);
  const [pathError, setPathError] = useState<string | null>(null);
  const [clusters, setClusters] = useState<Analytics | null>(null);
  const [clusterMode, setClusterMode] = useState(false);

  useEffect(() => {
    if (clusterMode && !clusters) api.analytics(investigationId).then(setClusters).catch(() => setClusterMode(false));
  }, [clusterMode, clusters, investigationId]);

  const clusterColor = useMemo(() => {
    const colors = new Map<number, string>();
    clusters?.communities.forEach((c, i) => colors.set(c.id, CLUSTER_COLORS[i % CLUSTER_COLORS.length]));
    return (nodeId: number) => {
      const cid = clusters?.membership[String(nodeId)];
      return cid !== undefined ? colors.get(cid) ?? "#64748b" : "#64748b";
    };
  }, [clusters]);

  useEffect(() => {
    if (pathEnds.from === undefined || pathEnds.to === undefined) return;
    setPathError(null);
    api.path(investigationId, pathEnds.from, pathEnds.to, showInferred)
      .then(setPath).catch((e) => { setPath(null); setPathError(e.message); });
  }, [pathEnds, investigationId, showInferred]);

  const view = useMemo(() => buildView(graph, { hiddenTypes, showInferred, collapsed }),
    [graph, hiddenTypes, showInferred, collapsed]);
  const matches = useMemo(() => new Set(searchNodes(view.nodes, query)), [view.nodes, query]);
  const presentTypes = ENTITY_TYPES.filter((t) => graph.nodes.some((n) => n.type === t));
  const nodeById = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph.nodes]);

  // (Re)build the Cytoscape instance when the visible element set changes.
  useEffect(() => {
    if (!container.current) return;
    const fg = themeColor("--fg");
    const line = themeColor("--line");
    const accent = themeColor("--accent");
    const inferred = themeColor("--inferred");
    const panel = themeColor("--panel");
    const elements: ElementDefinition[] = [
      ...view.nodes.map((n) => ({
        data: { id: `n${n.id}`, nid: n.id, label: n.folded ? `${n.label}  (+${n.folded})` : n.label,
          color: clusterMode && clusters ? clusterColor(n.id) : TYPE_COLORS[n.type] ?? "#94a3b8", seed: n.seed ? 1 : 0, size: n.seed ? 34 : 14 + Math.min(n.degree, 12) },
      })),
      ...view.edges.map((e) => ({
        data: { id: e.id, source: `n${e.source}`, target: `n${e.target}`, label: humanize(e.type),
          inferred: e.inferred ? 1 : 0, width: 0.8 + e.confidence * 1.4 },
      })),
    ];
    const prev = cyRef.current;
    const positions = new Map<string, cytoscape.Position>();
    prev?.nodes().forEach((n) => { positions.set(n.id(), { ...n.position() }); });
    prev?.destroy();

    const reuse = elements.every((el) => !("source" in el.data) ? positions.has(el.data.id as string) : true);
    const cy = cytoscape({
      container: container.current,
      elements,
      wheelSensitivity: 0.25,
      minZoom: 0.05,
      maxZoom: 4,
      style: [
        { selector: "node", style: {
          "background-color": "data(color)", width: "data(size)", height: "data(size)",
          label: "data(label)", color: fg, "font-size": 9, "text-valign": "bottom", "text-margin-y": 3,
          "text-max-width": "160px", "text-wrap": "ellipsis", "border-width": 0,
          "min-zoomed-font-size": 7,
        } },
        { selector: "node[seed = 1]", style: { "border-width": 3, "border-color": fg, "font-size": 11, "font-weight": "bold" } },
        { selector: "node.match", style: { "border-width": 3, "border-color": accent, "z-index": 10 } },
        { selector: "node.faded, edge.faded", style: { opacity: 0.15 } },
        { selector: "node.onpath", style: { "border-width": 4, "border-color": "#facc15", opacity: 1 } },
        { selector: "edge.onpath", style: { width: 4, "line-color": "#facc15", "target-arrow-color": "#facc15", opacity: 1, label: "data(label)", color: fg, "font-size": 9 } },
        { selector: "node:selected", style: { "border-width": 4, "border-color": accent } },
        { selector: "edge", style: {
          width: "data(width)", "line-color": line, "curve-style": "bezier",
          "target-arrow-shape": "triangle", "target-arrow-color": line, "arrow-scale": 0.7,
        } },
        { selector: "edge[inferred = 1]", style: { "line-style": "dashed", "line-color": inferred, "target-arrow-color": inferred } },
        { selector: "edge:selected, edge.hover", style: {
          label: "data(label)", "font-size": 9, color: fg, "text-background-color": panel,
          "text-background-opacity": 0.9, "text-background-padding": "2px", "line-color": accent, "target-arrow-color": accent,
        } },
      ],
      layout: reuse && positions.size
        ? { name: "preset", positions: (n: cytoscape.NodeSingular) => positions.get(n.id())! } as cytoscape.LayoutOptions
        : layoutFor(view.nodes.length),
    });
    cy.on("tap", "node", (evt) => setSelection({ kind: "node", id: evt.target.data("nid") }));
    cy.on("tap", "edge", (evt) => {
      const edge = view.edges.find((e) => e.id === evt.target.id());
      if (edge) setSelection({ kind: "edge", edge });
    });
    cy.on("tap", (evt) => { if (evt.target === cy) setSelection(null); });
    cy.on("dbltap", "node", (evt) => toggleCollapse(evt.target.data("nid")));
    cy.on("mouseover", "edge", (evt) => evt.target.addClass("hover"));
    cy.on("mouseout", "edge", (evt) => evt.target.removeClass("hover"));
    cyRef.current = cy;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, themeVersion, clusterMode, clusters]);

  // Path highlighting without rebuilding the graph.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass("onpath");
      if (!path) return;
      const nodes = new Set(path.nodes.map((n) => `n${n}`));
      const edges = new Set(path.edges);
      cy.nodes().forEach((n) => { if (nodes.has(n.id())) n.addClass("onpath"); });
      cy.edges().forEach((e) => { if (edges.has(e.id())) e.addClass("onpath"); });
    });
    const eles = cy.elements(".onpath");
    if (eles.length) cy.animate({ fit: { eles, padding: 80 } }, { duration: 200 });
  }, [path, view, clusterMode, clusters]);

  useEffect(() => () => { cyRef.current?.destroy(); cyRef.current = null; }, []);

  // Search highlighting without rebuilding the graph.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass("match faded");
      if (matches.size) {
        cy.nodes().forEach((n) => { n.addClass(matches.has(n.data("nid")) ? "match" : "faded"); });
        cy.edges().addClass("faded");
      }
    });
  }, [matches, view]);

  const toggleCollapse = (id: number) =>
    setCollapsed((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  const focusMatches = () => {
    const cy = cyRef.current;
    if (!cy || !matches.size) return;
    const els = cy.nodes().filter((n) => matches.has(n.data("nid")));
    if (els.length === 1) {
      // Fitting a single node would zoom to its full size; centre instead.
      cy.animate({ center: { eles: els }, zoom: Math.max(cy.zoom(), 1.2) }, { duration: 200 });
    } else {
      cy.animate({ fit: { eles: els, padding: 80 } }, { duration: 200 });
    }
    if (els.length === 1) setSelection({ kind: "node", id: els[0].data("nid") });
  };

  const exportPng = () => {
    const cy = cyRef.current;
    if (!cy) return;
    downloadBlob(`strxeye-${investigationId}-graph.png`, cy.png({ full: true, scale: 2, bg: themeColor("--bg"), output: "blob" }) as unknown as Blob);
  };
  const exportSvg = () => {
    const cy = cyRef.current;
    if (!cy) return;
    downloadText(`strxeye-${investigationId}-graph.svg`, cy.svg({ full: true, bg: themeColor("--bg") }), "image/svg+xml");
  };
  const exportJson = () =>
    downloadText(`strxeye-${investigationId}-graph.json`, JSON.stringify(graph, null, 2), "application/json");

  return (
    <div className="grid h-full grid-cols-[minmax(0,1fr)_minmax(320px,30%)]">
      <div className="flex min-w-0 flex-col">
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
          <form className="flex gap-1" onSubmit={(e) => { e.preventDefault(); focusMatches(); }}>
            <input className="input w-56 py-1" placeholder="Find node" value={query} onChange={(e) => setQuery(e.target.value)} aria-label="Find node" />
            <button className="btn btn-sm" disabled={!matches.size}>{matches.size ? `Go (${matches.size})` : "Go"}</button>
          </form>
          <div className="flex flex-wrap gap-1" role="group" aria-label="Entity types shown">
            {presentTypes.map((t) => {
              const on = !hiddenTypes.has(t);
              return (
                <button key={t} aria-pressed={on} title={on ? `Hide ${t}` : `Show ${t}`}
                  onClick={() => setHiddenTypes((s) => { const n = new Set(s); if (on) n.add(t); else n.delete(t); return n; })}
                  className={`chip gap-1 px-2 py-0.5 ${on ? "" : "opacity-40"}`} style={{ color: TYPE_COLORS[t], borderColor: `${TYPE_COLORS[t]}66` }}>
                  <span className="h-1.5 w-1.5 rounded-full" style={{ background: TYPE_COLORS[t] }} />{t}
                </button>
              );
            })}
          </div>
          <label className="flex items-center gap-1.5 text-xs">
            <input type="checkbox" className="accent-[rgb(var(--accent))]" checked={showInferred} onChange={(e) => setShowInferred(e.target.checked)} />
            <span className="text-inferred">inferred links</span>
          </label>
          <label className="flex items-center gap-1.5 text-xs">
            <input type="checkbox" className="accent-[rgb(var(--accent))]" checked={clusterMode} onChange={(e) => setClusterMode(e.target.checked)} />
            colour by cluster
          </label>
          <div className="ml-auto flex gap-1">
            <button className="btn btn-sm" title="Fit to screen" onClick={() => cyRef.current?.fit(undefined, 40)}><Icon name="fit" size={14} /></button>
            <button className="btn btn-sm" title="Re-run layout" onClick={() => cyRef.current?.layout(layoutFor(view.nodes.length)).run()}><Icon name="refresh" size={14} /></button>
            <button className="btn btn-sm" onClick={exportPng}>PNG</button>
            <button className="btn btn-sm" onClick={exportSvg}>SVG</button>
            <button className="btn btn-sm" onClick={exportJson}>JSON</button>
          </div>
        </div>
        <div className="relative min-h-0 flex-1">
          <div ref={container} className="absolute inset-0" data-testid="graph-canvas" />
          <div className="pointer-events-none absolute bottom-2 left-3 text-xxs text-muted">
            {view.nodes.length} nodes · {view.edges.length} edges
            {view.hiddenByType > 0 && ` · ${view.hiddenByType} hidden by type`}
            {view.hiddenByCollapse > 0 && ` · ${view.hiddenByCollapse} folded`}
            {" "}· double-click a node to fold or unfold its leaf neighbours
          </div>
        </div>
      </div>
      <aside className="min-w-0 overflow-auto border-l border-line bg-panel" aria-label="Selection details">
        {(path || pathError || pathEnds.from !== undefined) && (
          <div className="border-b border-line bg-raised/40 px-4 py-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="label">Shortest path</span>
              <button className="text-muted hover:text-fg" onClick={() => { setPath(null); setPathEnds({}); setPathError(null); }}>clear</button>
            </div>
            {pathError && <p className="text-warn">{pathError}{!showInferred && " (inferred links are excluded)"}</p>}
            {!path && !pathError && <p className="text-muted">From {nodeById.get(pathEnds.from!)?.value}. Select another node and choose Path to.</p>}
            {path && (
              <ol className="mt-1 space-y-0.5">
                {path.nodes.map((id, i) => {
                  const edge = graph.edges.find((e) => e.id === path.edges[i]);
                  return (
                    <li key={id}>
                      <span className="mono">{nodeById.get(id)?.value}</span>
                      {edge && <div className="pl-3 text-muted">↓ {humanize(edge.type)}{edge.inferred ? " (inferred)" : ""}</div>}
                    </li>
                  );
                })}
              </ol>
            )}
          </div>
        )}
        {clusterMode && clusters && (
          <div className="border-b border-line px-4 py-2 text-xs">
            <span className="label">Clusters</span>
            <ul className="mt-1 space-y-0.5">
              {clusters.communities.slice(0, 10).map((c, i) => (
                <li key={c.id} className="flex items-center gap-2">
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: CLUSTER_COLORS[i % CLUSTER_COLORS.length] }} />
                  <span className="mono truncate">{c.hub}</span>
                  <span className="ml-auto text-muted">{c.size}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {selection?.kind === "node" && (
          <>
            <div className="flex flex-wrap gap-2 border-b border-line px-4 py-2">
              <button className="btn btn-sm" title="Start a shortest-path search here" onClick={() => { setPath(null); setPathEnds({ from: selection.id }); }}>Path from</button>
              <button className="btn btn-sm" disabled={pathEnds.from === undefined || pathEnds.from === selection.id}
                title="Find the shortest connection to this node" onClick={() => setPathEnds((p) => ({ ...p, to: selection.id }))}>Path to</button>
              <button className="btn btn-sm" onClick={() => toggleCollapse(selection.id)}>
                {collapsed.has(selection.id) ? "Unfold leaves" : "Fold leaves"}
              </button>
              <button className="btn btn-sm" onClick={() => navigate({ page: "investigation", id: investigationId, tab: "entities", entity: selection.id })}>
                Open in Entities
              </button>
            </div>
            <EntityDetail compact investigationId={investigationId} entityId={selection.id}
              onSelectEntity={(id) => {
                setSelection({ kind: "node", id });
                const node = cyRef.current?.$id(`n${id}`);
                if (node && node.length) { cyRef.current?.elements().unselect(); node.select(); cyRef.current?.animate({ center: { eles: node } }, { duration: 200 }); }
              }} />
          </>
        )}
        {selection?.kind === "edge" && <EdgeDetail edge={selection.edge} nodes={nodeById} investigationId={investigationId} />}
        {!selection && (
          <div className="space-y-3 p-4 text-muted">
            <p>Select a node or relationship to inspect it.</p>
            <ul className="space-y-1.5 text-xxs">
              <li><span className="inline-block w-8 border-t-2 border-line align-middle" /> observed by a source</li>
              <li><span className="inline-block w-8 border-t-2 border-dashed border-inferred align-middle" /> inferred by correlation (not a source fact)</li>
              <li>Thicker lines carry higher confidence. Seeds have a ring.</li>
            </ul>
          </div>
        )}
      </aside>
    </div>
  );
}

function layoutFor(count: number): cytoscape.LayoutOptions {
  if (count > 700) return { name: "concentric", concentric: (n: cytoscape.NodeSingular) => n.degree(false), levelWidth: () => 3, animate: false } as cytoscape.LayoutOptions;
  return {
    name: "cose", animate: false, randomize: true, nodeRepulsion: () => 9000, idealEdgeLength: () => 70,
    numIter: count > 300 ? 600 : 1200, padding: 30,
  } as cytoscape.LayoutOptions;
}

function EdgeDetail({ edge, nodes, investigationId }: { edge: GraphEdge; nodes: Map<number, Graph["nodes"][number]>; investigationId: string }) {
  const [evidence, setEvidence] = useState<string | null>(null);
  const src = nodes.get(edge.source)!;
  const dst = nodes.get(edge.target)!;
  return (
    <div className="space-y-4 p-4">
      <div>
        <span className={`chip ${edge.inferred ? "border-inferred/60 text-inferred" : "border-ok/50 text-ok"}`}>
          {edge.inferred ? "inferred" : "observed"}
        </span>
        <h2 className="mt-1 text-[15px] font-semibold">{humanize(edge.type)}</h2>
      </div>
      <div className="space-y-1">
        <div className="flex items-center gap-2"><TypeBadge type={src.type} /><span className="mono break-all">{src.value}</span></div>
        <div className="pl-2 text-muted">↓</div>
        <div className="flex items-center gap-2"><TypeBadge type={dst.type} /><span className="mono break-all">{dst.value}</span></div>
      </div>
      <div className="flex items-center gap-2"><span className="label">Confidence</span><Confidence value={edge.confidence} /></div>
      {edge.inferred ? (
        <div className="rounded border border-inferred/40 bg-inferred/10 p-3">
          <div className="label mb-1 text-inferred">Why this was suggested</div>
          <p>{edge.explanation}</p>
        </div>
      ) : (
        <div>
          <div className="label mb-1">Provenance ({edge.provenance?.length ?? 0})</div>
          <ul className="divide-y divide-line/60 rounded border border-line">
            {edge.provenance?.map((p, i) => (
              <li key={i} className="px-3 py-1.5">
                <div className="flex justify-between"><span className="mono">{p.origin}</span><Confidence value={p.confidence} /></div>
                <div className="text-xxs text-muted">{formatTime(p.collected_at)} · run {p.run_id}</div>
                {p.evidence_id && <button className="text-xxs text-accent hover:underline" onClick={() => setEvidence(p.evidence_id)}>view evidence</button>}
              </li>
            ))}
          </ul>
        </div>
      )}
      {evidence && <EvidenceViewer investigationId={investigationId} evidenceId={evidence} onClose={() => setEvidence(null)} />}
    </div>
  );
}

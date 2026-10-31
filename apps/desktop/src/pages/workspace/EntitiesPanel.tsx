import { useEffect, useState } from "react";
import { api } from "../../api";
import { EntityDetail } from "../../components/EntityDetail";
import { EmptyState, ErrorBanner, Spinner, TypeBadge } from "../../components/ui";
import { entitySubtitle, href, navigate, relativeTime, useLoad } from "../../lib";
import { ENTITY_TYPES, type EntityType } from "../../types";
import type { PanelProps } from "../Workspace";

const PAGE = 500;

export function EntitiesPanel({ inv, route }: PanelProps) {
  const [type, setType] = useState<EntityType | "">("");
  const [search, setSearch] = useState("");
  const [debounced, setDebounced] = useState("");
  const [limit, setLimit] = useState(PAGE);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(search.trim()), 200);
    return () => clearTimeout(t);
  }, [search]);
  useEffect(() => setLimit(PAGE), [type, debounced]);

  const rows = useLoad(() => api.entities(inv.id, { type: type || undefined, search: debounced || undefined, limit }),
    [inv.id, type, debounced, limit, inv.updated_at]);

  const total = Object.values(inv.counts).reduce((a, b) => a + (b ?? 0), 0);
  const select = (id: number) => navigate({ ...route, tab: "entities", entity: id });

  if (total === 0) {
    return (
      <EmptyState title="No entities yet"
        action={<a className="btn-primary" href={href({ ...route, tab: "collect", entity: undefined })}>Start collecting</a>}>
        Entities appear here after a collection run.
      </EmptyState>
    );
  }

  return (
    <div className="grid h-full grid-cols-[minmax(0,1fr)_minmax(380px,40%)]">
      <div className="flex min-w-0 flex-col border-r border-line">
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
          <input className="input max-w-xs" placeholder="Search values  ( / )" value={search} id="entity-search"
            onChange={(e) => setSearch(e.target.value)} aria-label="Search entities"
            onKeyDown={(e) => e.key === "Escape" && setSearch("")} />
          <div className="flex flex-wrap gap-1" role="group" aria-label="Filter by type">
            <button className={`chip px-2 py-0.5 ${type === "" ? "border-accent text-accent" : "text-muted hover:text-fg"}`} onClick={() => setType("")}>
              all {total}
            </button>
            {ENTITY_TYPES.filter((t) => inv.counts[t]).map((t) => (
              <button key={t} aria-pressed={type === t} onClick={() => setType(type === t ? "" : t)}
                className={`chip px-2 py-0.5 ${type === t ? "border-accent text-accent" : "text-muted hover:text-fg"}`}>
                {t} {inv.counts[t]}
              </button>
            ))}
          </div>
        </div>
        <SlashFocus />
        <div className="min-h-0 flex-1 overflow-auto">
          {rows.error && <div className="p-3"><ErrorBanner message={rows.error} onRetry={rows.reload} /></div>}
          {rows.loading && !rows.data && <div className="p-3 text-muted"><Spinner /> Loading</div>}
          {rows.data && (
            <table className="tbl table-fixed">
              <thead><tr><th className="w-32">Type</th><th>Value</th><th className="w-16 text-right">Obs.</th><th className="w-16 text-right">Links</th><th className="w-28">Last seen</th></tr></thead>
              <tbody>
                {rows.data.map((e) => (
                  <tr key={e.id} onClick={() => select(e.id)} aria-selected={route.entity === e.id}
                    className={`cursor-pointer ${route.entity === e.id ? "bg-accent/10" : "hover:bg-raised/60"}`}>
                    <td><TypeBadge type={e.type} /></td>
                    <td className="max-w-0" title={e.value}>
                      <a href={href({ ...route, tab: "entities", entity: e.id })} onClick={(ev) => ev.preventDefault()}
                        className="mono block truncate hover:text-accent">{e.value}</a>
                      {entitySubtitle(e.type, e.attributes) && (
                        <span className="block truncate text-xxs text-muted">{entitySubtitle(e.type, e.attributes)}</span>
                      )}
                    </td>
                    <td className="text-right tabular-nums">{e.observations}</td>
                    <td className="text-right tabular-nums">{e.relationships}</td>
                    <td className="whitespace-nowrap text-muted">{relativeTime(e.last_seen)}</td>
                  </tr>
                ))}
                {rows.data.length === 0 && <tr><td colSpan={5} className="py-6 text-center text-muted">No entity matches the filter.</td></tr>}
              </tbody>
            </table>
          )}
          {rows.data && rows.data.length >= limit && (
            <div className="p-3 text-center"><button className="btn btn-sm" onClick={() => setLimit(limit + PAGE)}>Load more</button></div>
          )}
        </div>
      </div>
      <aside className="min-w-0 overflow-auto bg-panel" aria-label="Entity details">
        {route.entity
          ? <EntityDetail investigationId={inv.id} entityId={route.entity} onSelectEntity={select} />
          : <EmptyState title="Select an entity">Its observations, sources, evidence and relationships appear here.</EmptyState>}
      </aside>
    </div>
  );
}

/** "/" focuses the entity search, as in most investigation tools. */
function SlashFocus() {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName;
      if (e.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA") {
        e.preventDefault();
        document.getElementById("entity-search")?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  return null;
}

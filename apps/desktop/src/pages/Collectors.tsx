import { useApp } from "../App";
import { TypeBadge } from "../components/ui";

export function CollectorsPage() {
  const { meta } = useApp();
  const collectors = meta?.collectors ?? [];
  return (
    <div className="h-full overflow-auto">
      <header className="border-b border-line px-6 py-4">
        <h1 className="text-lg font-semibold">Collectors</h1>
        <p className="max-w-3xl text-muted">
          Each collector queries one kind of source. Passive collectors only contact the third-party services
          listed. Direct collectors connect to the target's own servers and run only when you allow it for a run
          or enable it in Settings.
        </p>
      </header>
      <div className="grid gap-3 p-6 lg:grid-cols-2">
        {collectors.map((c) => (
          <article key={c.name} className="card p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h2 className="font-semibold">{c.title}</h2>
                <div className="mono text-muted">{c.name} · v{c.version}</div>
              </div>
              <span className={`chip ${c.direct ? "border-warn/50 text-warn" : "border-ok/50 text-ok"}`}>
                {c.direct ? "direct" : "passive"}
              </span>
            </div>
            <p className="mt-2">{c.description}</p>
            <dl className="mt-3 grid grid-cols-[110px_1fr] gap-y-1.5">
              <dt className="label pt-0.5">Accepts</dt>
              <dd className="flex flex-wrap gap-1">{c.accepts.map((t) => <TypeBadge key={t} type={t} />)}</dd>
              <dt className="label pt-0.5">Contacts</dt>
              <dd>{c.direct ? "The target's own servers" : c.sources.join(", ")}</dd>
            </dl>
          </article>
        ))}
      </div>
    </div>
  );
}

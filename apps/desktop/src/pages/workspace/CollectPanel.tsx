import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../../api";
import { useApp } from "../../App";
import { ErrorBanner, Icon, Spinner, StatusText, TypeBadge, useToast } from "../../components/ui";
import { formatTime, guessTargetType, href, relativeTime } from "../../lib";
import type { CollectorInfo, RunDetail } from "../../types";
import type { PanelProps } from "../Workspace";

const POLL_MS = 800;

export function CollectPanel({ inv, reload }: PanelProps) {
  const { meta, reloadInvestigations } = useApp();
  const toast = useToast();
  const [target, setTarget] = useState("");
  const [allowDirect, setAllowDirect] = useState(meta?.settings.collection.allow_direct ?? false);
  const [expand, setExpand] = useState(true);
  const [excluded, setExcluded] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [runId, setRunId] = useState<string | null>(() => inv.runs.find((r) => r.status === "running")?.id ?? null);
  const [run, setRun] = useState<RunDetail | null>(null);
  const [inspect, setInspect] = useState<string | null>(null);

  const type = guessTargetType(target);
  const [keySet, setKeySet] = useState<Set<string>>(new Set());
  useEffect(() => {
    api.keys().then((ks) => setKeySet(new Set(ks.filter((k) => k.source).map((k) => k.name))))
      .catch(() => setKeySet(new Set()));
  }, []);
  const applicable = useMemo(
    () => (meta?.collectors ?? []).filter((c) => type && c.accepts.includes(type as CollectorInfo["accepts"][number])),
    [meta, type],
  );
  const usable = (c: CollectorInfo) => (!c.direct || allowDirect)
    && (c.requires_key === null || keySet.has(c.requires_key));
  const selected = applicable.filter((c) => !excluded.has(c.name) && usable(c));

  // Poll the active run until it leaves the "running" state.
  const reloadRef = useRef(reload);
  reloadRef.current = reload;
  useEffect(() => {
    if (!runId) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const detail = await api.run(runId);
        if (stopped) return;
        setRun(detail);
        if (detail.status === "running") {
          timer = setTimeout(tick, POLL_MS);
        } else {
          setRunId(null);
          reloadRef.current();
          reloadInvestigations();
          const failed = detail.collectors.filter((c) => c.status === "error" || c.status === "timeout").length;
          toast(`Collection ${detail.status}` + (failed ? ` with ${failed} failed collector(s)` : ""), failed ? "error" : "info");
        }
      } catch (e) {
        if (!stopped) setError((e as Error).message);
      }
    };
    tick();
    return () => { stopped = true; clearTimeout(timer); };
  }, [runId, reloadInvestigations, toast]);

  const start = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const names = selected.map((c) => c.name);
      const { run_id } = await api.startRun(inv.id, {
        target,
        collectors: names.length === applicable.filter(usable).length ? undefined : names,
        direct: allowDirect,
        expand: expand && type === "domain",
      });
      setRun(null);
      setRunId(run_id);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const running = runId !== null;

  return (
    <div className="grid h-full grid-cols-1 overflow-auto 2xl:grid-cols-[minmax(380px,460px)_1fr]">
      <section className="border-b border-line p-5 2xl:border-b-0 2xl:border-r">
        <form onSubmit={start} className="max-w-5xl space-y-4">
          <div className="space-y-1">
            <label htmlFor="target" className="label">Target</label>
            <div className="flex gap-2">
              <input id="target" className="input mono" value={target} onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com, 1.1.1.1, AS13335, a file hash, or org:Company" autoComplete="off" spellCheck={false} disabled={running} />
            </div>
            <div className="h-4 text-xxs text-muted">
              {target && (type ? <>Detected: <TypeBadge type={type} /></> : "Not recognised. Companies need the org: prefix, e.g. org:Cloudflare")}
            </div>
          </div>

          {type && applicable.length === 0 && (
            <ErrorBanner message={`No collectors support ${type} targets yet.`} />
          )}
          {applicable.length > 0 && (
            <fieldset className="grid gap-1.5 md:grid-cols-2">
              <legend className="label mb-1">Collectors</legend>
              {applicable.map((c) => {
                const needsKey = c.requires_key !== null && !keySet.has(c.requires_key);
                const blocked = (c.direct && !allowDirect) || needsKey;
                return (
                  <label key={c.name} className={`flex items-start gap-2 rounded border border-line px-2.5 py-1.5 ${blocked ? "opacity-50" : ""}`}>
                    <input type="checkbox" className="mt-0.5 accent-[rgb(var(--accent))]" disabled={blocked || running}
                      checked={!excluded.has(c.name) && !blocked}
                      onChange={(e) => setExcluded((s) => {
                        const n = new Set(s);
                        if (e.target.checked) n.delete(c.name); else n.add(c.name);
                        return n;
                      })} />
                    <span className="flex-1">
                      <span className="font-medium">{c.title}</span>
                      {c.direct && <span className="chip ml-2 border-warn/50 text-warn">direct</span>}
                      {needsKey && <a href="#/settings" className="chip ml-2 border-line text-muted hover:text-accent">needs API key</a>}
                      <span className="block text-xxs text-muted">{c.direct ? "Connects to the target's servers" : `Queries ${c.sources.join(", ")}`}</span>
                    </span>
                  </label>
                );
              })}
            </fieldset>
          )}

          <div className="space-y-2">
            <label className="flex items-start gap-2">
              <input type="checkbox" className="mt-0.5 accent-[rgb(var(--accent))]" checked={allowDirect} disabled={running}
                onChange={(e) => setAllowDirect(e.target.checked)} />
              <span>Allow direct collection
                <span className="block text-xxs text-muted">Fetches the homepage, robots.txt and TLS certificate from the target. The target can see and log these requests. Only enable for targets you are authorised to contact.</span>
              </span>
            </label>
            <label className="flex items-start gap-2">
              <input type="checkbox" className="mt-0.5 accent-[rgb(var(--accent))]" checked={expand && type === "domain"} disabled={running || type !== "domain"}
                onChange={(e) => setExpand(e.target.checked)} />
              <span>Expand discovered IPs
                <span className="block text-xxs text-muted">Look up network owner, BGP origin and reverse DNS for addresses the domain resolves to.</span>
              </span>
            </label>
          </div>

          {error && <ErrorBanner message={error} />}
          <div className="flex gap-2">
            <button className="btn-primary" disabled={running || !type || selected.length === 0}>
              <Icon name="play" size={14} /> Collect
            </button>
            {running && (
              <button type="button" className="btn-danger" onClick={() => runId && api.cancelRun(runId)}>
                <Icon name="stop" size={14} /> Cancel
              </button>
            )}
          </div>
        </form>
      </section>

      <section className="min-w-0 p-5">
        {run && <RunProgress run={run} />}
        <h2 className="label mb-2 mt-1">Run history</h2>
        {inv.runs.length === 0 ? (
          <p className="text-muted">No collection runs yet. Enter a target to start.</p>
        ) : (
          <div className="card overflow-x-auto">
            <table className="tbl">
              <thead><tr><th>Run</th><th>Target</th><th>Started</th><th>Status</th><th className="text-right">Collectors</th><th className="text-right">Failed</th><th className="text-right">Observations</th><th /></tr></thead>
              <tbody>
                {inv.runs.map((r) => (
                  <tr key={r.id} className="hover:bg-raised/60">
                    <td className="mono">{r.id}</td>
                    <td><span className="mono">{r.target_value}</span>{r.options.direct && <span className="chip ml-1.5 border-warn/50 text-warn">direct</span>}</td>
                    <td className="whitespace-nowrap text-muted" title={formatTime(r.started_at)}>{relativeTime(r.started_at)}</td>
                    <td><StatusText status={r.status} /></td>
                    <td className="text-right tabular-nums">{r.collector_count}</td>
                    <td className={`text-right tabular-nums ${r.failed_count ? "text-bad" : ""}`}>{r.failed_count}</td>
                    <td className="text-right tabular-nums">{r.observation_count}</td>
                    <td><button className="btn btn-sm" onClick={() => setInspect(inspect === r.id ? null : r.id)}>{inspect === r.id ? "Hide" : "Details"}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {inspect && <RunInspector runId={inspect} />}
      </section>
    </div>
  );
}

function RunProgress({ run }: { run: RunDetail }) {
  return (
    <div className="card mb-5 p-4">
      <div className="mb-2 flex items-center gap-2">
        {run.status === "running" && <Spinner className="text-accent" />}
        <span className="font-semibold">Run {run.id}</span>
        <span className="mono text-muted">{run.target_value}</span>
        <span className="ml-auto"><StatusText status={run.status} /></span>
      </div>
      <CollectorTable rows={run.collectors} active={run.active} />
    </div>
  );
}

function RunInspector({ runId }: { runId: string }) {
  const [run, setRun] = useState<RunDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.run(runId).then(setRun).catch((e) => setError(e.message)); }, [runId]);
  if (error) return <div className="mt-3"><ErrorBanner message={error} /></div>;
  if (!run) return <div className="mt-3 text-muted"><Spinner /> Loading run</div>;
  return (
    <div className="card mt-3 p-4">
      <div className="mb-2 text-muted">Run {run.id} · started {formatTime(run.started_at)} · finished {formatTime(run.finished_at)} ·{" "}
        options: {run.options.collectors?.join(", ") ?? "all applicable"}{run.options.direct ? ", direct" : ""}{run.options.expand ? ", expand" : ""}</div>
      <CollectorTable rows={run.collectors} active={[]} />
      <a className="mt-2 inline-block text-accent hover:underline" href={href({ page: "investigation", id: run.investigation_id, tab: "entities" })}>View entities</a>
    </div>
  );
}

function CollectorTable({ rows, active }: { rows: RunDetail["collectors"]; active: string[] }) {
  return (
    <table className="tbl">
      <thead><tr><th>Collector</th><th>Target</th><th>Status</th><th className="text-right">Time</th><th>Detail</th></tr></thead>
      <tbody>
        {active.map((a) => {
          const [collector, ...rest] = a.split(":");
          return (
            <tr key={`active-${a}`}>
              <td className="mono">{collector}</td><td className="mono">{rest.join(":")}</td>
              <td className="text-accent"><Spinner /> running</td><td /><td />
            </tr>
          );
        })}
        {rows.map((c) => (
          <tr key={c.id}>
            <td className="mono">{c.collector}</td>
            <td className="mono">{c.target_value}</td>
            <td><StatusText status={c.status} /></td>
            <td className="text-right tabular-nums text-muted">
              {((new Date(c.finished_at).getTime() - new Date(c.started_at).getTime()) / 1000).toFixed(1)}s
            </td>
            <td className={c.error ? "text-bad" : "text-muted"}>{c.error ?? c.notes.join("; ")}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

import { useEffect, useState } from "react";
import { api } from "../api";
import { useApp, type ThemeChoice } from "../App";
import { ErrorBanner, Spinner, useToast } from "../components/ui";
import type { KeyStatus, UpdateInfo } from "../types";

interface Field {
  key: string;
  label: string;
  help: string;
  kind: "bool" | "number" | "list";
}

const FIELDS: Field[] = [
  { key: "collection.allow_direct", kind: "bool", label: "Allow direct collection by default",
    help: "When on, HTTP and TLS collectors run on every domain without asking. They connect to the target's servers, which the target can log." },
  { key: "collection.collector_timeout", kind: "number", label: "Collector timeout (seconds)",
    help: "A collector still running after this is stopped and recorded as timed out." },
  { key: "network.timeout", kind: "number", label: "Request timeout (seconds)", help: "Per HTTP request or DNS query." },
  { key: "network.retries", kind: "number", label: "Retries", help: "Retries for transient failures (HTTP 429/5xx, timeouts)." },
  { key: "collection.max_subdomains", kind: "number", label: "Max subdomains per domain",
    help: "Certificate Transparency can return thousands of names; extra ones are counted but not stored." },
  { key: "collection.max_certificates", kind: "number", label: "Max certificates per domain", help: "Newest certificates are kept." },
  { key: "collection.max_expansions", kind: "number", label: "Max IPs to expand", help: "With expansion on, how many discovered IPs get ASN/owner lookups." },
  { key: "dns.nameservers", kind: "list", label: "DNS resolvers",
    help: "Comma-separated IP addresses. Empty uses the system resolver. Your resolver sees every name you query." },
];

function getValue(settings: Record<string, Record<string, unknown>>, key: string): unknown {
  const [section, name] = key.split(".");
  return settings[section]?.[name];
}

export function SettingsPage() {
  const { meta, reloadMeta, theme, setTheme } = useApp();
  const toast = useToast();
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  if (!meta) return null;
  const settings = meta.settings as unknown as Record<string, Record<string, unknown>>;

  const save = async (field: Field, raw: string) => {
    try {
      await api.changeSetting(field.key, raw);
      setDrafts((d) => { const n = { ...d }; delete n[field.key]; return n; });
      reloadMeta();
      toast(`Saved ${field.label.toLowerCase()}`);
    } catch (e) {
      toast((e as Error).message, "error");
    }
  };

  return (
    <div className="h-full overflow-auto">
      <header className="border-b border-line px-6 py-4">
        <h1 className="text-lg font-semibold">Settings</h1>
        <p className="text-muted">Stored in the same config file the CLI uses (<span className="mono">strxeye config show</span>).</p>
      </header>
      <div className="max-w-3xl space-y-6 p-6">
        <section className="card p-4">
          <h2 className="mb-3 font-semibold">Appearance</h2>
          <div className="flex gap-2" role="radiogroup" aria-label="Theme">
            {(["dark", "light", "system"] as ThemeChoice[]).map((t) => (
              <button key={t} role="radio" aria-checked={theme === t} onClick={() => setTheme(t)}
                className={theme === t ? "btn-primary" : "btn"}>
                {t === "system" ? "Follow system" : t[0].toUpperCase() + t.slice(1)}
              </button>
            ))}
          </div>
        </section>

        <section className="card divide-y divide-line">
          <h2 className="px-4 py-3 font-semibold">Collection</h2>
          {FIELDS.map((f) => {
            const current = getValue(settings, f.key);
            const shown = f.kind === "list" ? (current as string[]).join(", ") : String(current);
            const draft = drafts[f.key];
            return (
              <div key={f.key} className="grid gap-3 px-4 py-3 sm:grid-cols-[1fr_220px]">
                <div>
                  <label htmlFor={f.key} className="font-medium">{f.label}</label>
                  <p className="text-xxs text-muted">{f.help}</p>
                </div>
                {f.kind === "bool" ? (
                  <label className="flex items-center gap-2 justify-self-start sm:justify-self-end">
                    <input id={f.key} type="checkbox" className="h-4 w-4 accent-[rgb(var(--accent))]" checked={Boolean(current)}
                      onChange={(e) => save(f, String(e.target.checked))} />
                    {current ? "On" : "Off"}
                  </label>
                ) : (
                  <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); if (draft !== undefined) save(f, draft); }}>
                    <input id={f.key} className="input" value={draft ?? shown}
                      inputMode={f.kind === "number" ? "decimal" : undefined}
                      placeholder={f.kind === "list" ? "system default" : undefined}
                      onChange={(e) => setDrafts((d) => ({ ...d, [f.key]: e.target.value }))} />
                    <button className="btn" disabled={draft === undefined || draft === shown}>Save</button>
                  </form>
                )}
              </div>
            );
          })}
        </section>

        <KeysSection />
        <UpdatesSection checkOnStart={meta.settings.updates.check_on_start}
          onToggle={(v) => save({ key: "updates.check_on_start", kind: "bool", label: "Update check", help: "" }, String(v))} />

        <section className="card p-4">
          <h2 className="mb-2 font-semibold">About this installation</h2>
          <dl className="grid grid-cols-[140px_1fr] gap-y-1">
            <dt className="text-muted">Version</dt><dd className="mono">{meta.version}</dd>
            <dt className="text-muted">Database</dt><dd className="mono break-all">{meta.database}</dd>
            <dt className="text-muted">Trusted plugins</dt>
            <dd>{meta.settings.plugins.trusted.length ? meta.settings.plugins.trusted.join(", ") : "None. Manage with strxeye plugins."}</dd>
            <dt className="text-muted">Telemetry</dt><dd>None. STRX EYE sends nothing anywhere except the queries collectors make.</dd>
          </dl>
        </section>
      </div>
    </div>
  );
}

function KeysSection() {
  const toast = useToast();
  const [keys, setKeys] = useState<KeyStatus[] | null>(null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const load = () => api.keys().then(setKeys).catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  return (
    <section className="card divide-y divide-line">
      <div className="px-4 py-3">
        <h2 className="font-semibold">API keys</h2>
        <p className="text-xxs text-muted">Optional. Stored in the operating system's credential store (Windows Credential Manager, macOS Keychain), never in STRX EYE's files. Keys are write-only here: they are never shown again.</p>
      </div>
      {error && <div className="p-4"><ErrorBanner message={error} /></div>}
      {!keys && !error && <div className="p-4 text-muted"><Spinner /> Loading</div>}
      {keys?.map((k) => (
        <form key={k.name} className="grid gap-3 px-4 py-3 sm:grid-cols-[1fr_320px]" onSubmit={async (e) => {
          e.preventDefault();
          try {
            await api.setKey(k.name, drafts[k.name] ?? "");
            setDrafts((d) => ({ ...d, [k.name]: "" }));
            toast(`Saved ${k.name} key`);
            load();
          } catch (err) { toast((err as Error).message, "error"); }
        }}>
          <div>
            <div className="font-medium">{k.name}</div>
            <p className="text-xxs text-muted">{k.description}</p>
            <p className={`text-xxs ${k.source ? "text-ok" : "text-muted"}`}>
              {k.source === "keychain" ? "Set (system keychain)" : k.source === "environment" ? "Set via environment variable" : "Not set"}
            </p>
          </div>
          <div className="flex gap-2">
            <input type="password" autoComplete="off" className="input" placeholder={k.source ? "Replace key" : "Paste key"}
              value={drafts[k.name] ?? ""} onChange={(e) => setDrafts((d) => ({ ...d, [k.name]: e.target.value }))}
              aria-label={`${k.name} API key`} />
            <button className="btn" disabled={!(drafts[k.name] ?? "").trim()}>Save</button>
            {k.source === "keychain" && (
              <button type="button" className="btn-danger" onClick={async () => {
                await api.deleteKey(k.name).catch((err) => toast(err.message, "error"));
                load();
              }}>Remove</button>
            )}
          </div>
        </form>
      ))}
    </section>
  );
}

function UpdatesSection({ checkOnStart, onToggle }: { checkOnStart: boolean; onToggle: (v: boolean) => void }) {
  const toast = useToast();
  const [info, setInfo] = useState<UpdateInfo | null>(null);
  const [busy, setBusy] = useState<"check" | "install" | null>(null);
  const [error, setError] = useState<string | null>(null);

  const check = async () => {
    setBusy("check");
    setError(null);
    try { setInfo(await api.checkUpdate(true)); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(null); }
  };
  const install = async () => {
    setBusy("install");
    setError(null);
    try {
      const r = await api.installUpdate();
      toast(`Installing ${r.installing}. STRX EYE will close and restart.`);
    } catch (e) { setError((e as Error).message); setBusy(null); }
  };

  return (
    <section className="card p-4">
      <h2 className="mb-1 font-semibold">Updates</h2>
      <p className="mb-3 text-xxs text-muted">Checks GitHub Releases. The check sends no investigation data. Installers are verified against the SHA-256 checksums published with the release before they run.</p>
      <label className="mb-3 flex items-center gap-2">
        <input type="checkbox" className="h-4 w-4 accent-[rgb(var(--accent))]" checked={checkOnStart} onChange={(e) => onToggle(e.target.checked)} />
        Check for updates when the app starts
      </label>
      <div className="flex flex-wrap items-center gap-2">
        <button className="btn" onClick={check} disabled={busy !== null}>{busy === "check" ? <Spinner /> : null} Check now</button>
        {info?.newer && info.can_self_install && (
          <button className="btn-primary" onClick={install} disabled={busy !== null}>
            {busy === "install" ? <Spinner /> : null} Download and install {info.latest}
          </button>
        )}
        {info && !info.newer && <span className="text-ok">You have the latest version ({info.current}).</span>}
        {info?.newer && !info.can_self_install && (
          <span>Version {info.latest} is available. <a className="text-accent hover:underline" href={info.release_url} target="_blank" rel="noreferrer noopener">Release page</a> · pip users: <span className="mono">pip install -U strxeye</span></span>
        )}
      </div>
      {info?.newer && info.notes && (
        <pre className="mt-3 max-h-48 overflow-auto whitespace-pre-wrap rounded border border-line bg-bg p-3 text-xs">{info.notes}</pre>
      )}
      {error && <div className="mt-3"><ErrorBanner message={error} /></div>}
    </section>
  );
}

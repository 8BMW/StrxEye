import { useState } from "react";
import { api } from "../api";
import { useApp, type ThemeChoice } from "../App";
import { useToast } from "../components/ui";

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

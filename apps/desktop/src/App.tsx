import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { CommandPalette, type Command } from "./components/CommandPalette";
import { LogoMark, Wordmark } from "./components/Logo";
import { NewInvestigationDialog } from "./components/NewInvestigationDialog";
import { ErrorBanner, Icon, Kbd, Spinner, ToastProvider } from "./components/ui";
import { href, navigate, useLoad, useRoute, WORKSPACE_TABS, type Route } from "./lib";
import { AuditPage } from "./pages/Audit";
import { CollectorsPage } from "./pages/Collectors";
import { Overview } from "./pages/Overview";
import { SettingsPage } from "./pages/Settings";
import { Workspace } from "./pages/Workspace";
import type { InvestigationSummary, Meta } from "./types";

export type ThemeChoice = "dark" | "light" | "system";

interface AppState {
  meta: Meta | undefined;
  reloadMeta: () => void;
  investigations: InvestigationSummary[];
  reloadInvestigations: () => void;
  theme: ThemeChoice;
  setTheme: (t: ThemeChoice) => void;
  openNewInvestigation: () => void;
}

const AppContext = createContext<AppState>(null as unknown as AppState);
export const useApp = () => useContext(AppContext);

function readTheme(): ThemeChoice {
  try {
    return (localStorage.getItem("strxeye.theme") as ThemeChoice) || "system";
  } catch {
    return "system";
  }
}

function applyTheme(choice: ThemeChoice) {
  const resolved = choice === "system"
    ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
    : choice;
  document.documentElement.dataset.theme = resolved;
}

export default function App() {
  const route = useRoute();
  const meta = useLoad(() => api.meta(), []);
  const invs = useLoad(() => api.investigations(), []);
  const [theme, setThemeState] = useState<ThemeChoice>(readTheme);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [newOpen, setNewOpen] = useState(false);

  const setTheme = useCallback((t: ThemeChoice) => {
    setThemeState(t);
    try { localStorage.setItem("strxeye.theme", t); } catch { /* storage unavailable */ }
  }, []);
  useEffect(() => applyTheme(theme), [theme]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      } else if (mod && e.altKey && e.key.toLowerCase() === "n") {
        e.preventDefault();
        setNewOpen(true);
      } else if (e.altKey && /^[1-6]$/.test(e.key) && route.page === "investigation") {
        e.preventDefault();
        navigate({ ...route, tab: WORKSPACE_TABS[Number(e.key) - 1], entity: undefined });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [route]);

  const state = useMemo<AppState>(() => ({
    meta: meta.data,
    reloadMeta: meta.reload,
    investigations: invs.data ?? [],
    reloadInvestigations: invs.reload,
    theme,
    setTheme,
    openNewInvestigation: () => setNewOpen(true),
  }), [meta.data, meta.reload, invs.data, invs.reload, theme, setTheme]);

  const commands = useMemo<Command[]>(() => {
    const list: Command[] = [
      { id: "new", label: "New investigation", hint: "Ctrl+Alt+N", run: () => setNewOpen(true) },
      { id: "go-overview", label: "Go to Overview", run: () => navigate({ page: "overview" }) },
      { id: "go-collectors", label: "Go to Collectors", run: () => navigate({ page: "collectors" }) },
      { id: "go-settings", label: "Go to Settings", run: () => navigate({ page: "settings" }) },
      { id: "go-audit", label: "Go to Audit log", run: () => navigate({ page: "audit" }) },
      { id: "theme-dark", label: "Theme: dark", run: () => setTheme("dark") },
      { id: "theme-light", label: "Theme: light", run: () => setTheme("light") },
      { id: "theme-system", label: "Theme: follow system", run: () => setTheme("system") },
    ];
    if (route.page === "investigation") {
      for (const [i, tab] of WORKSPACE_TABS.entries()) {
        list.push({ id: `tab-${tab}`, label: `Show ${tab}`, hint: `Alt+${i + 1}`,
          run: () => navigate({ ...route, tab, entity: undefined }) });
      }
    }
    for (const inv of invs.data ?? []) {
      list.push({ id: `open-${inv.id}`, label: `Open: ${inv.name}`, hint: inv.id,
        run: () => navigate({ page: "investigation", id: inv.id, tab: "entities" }) });
    }
    return list;
  }, [invs.data, route, setTheme]);

  return (
    <ToastProvider>
      <AppContext.Provider value={state}>
        <div className="flex h-full">
          <Sidebar route={route} onPalette={() => setPaletteOpen(true)} />
          <main className="flex min-w-0 flex-1 flex-col overflow-hidden">
            {meta.error && !meta.data ? (
              <div className="m-6"><ErrorBanner message={meta.error} onRetry={meta.reload} /></div>
            ) : !meta.data ? (
              <div className="m-6 flex items-center gap-2 text-muted"><Spinner /> Connecting to engine…</div>
            ) : (
              <Page route={route} />
            )}
          </main>
        </div>
        {paletteOpen && <CommandPalette commands={commands} onClose={() => setPaletteOpen(false)} />}
        {newOpen && <NewInvestigationDialog onClose={() => setNewOpen(false)} />}
      </AppContext.Provider>
    </ToastProvider>
  );
}

function Page({ route }: { route: Route }) {
  switch (route.page) {
    case "investigation":
      return <Workspace key={route.id} route={route} />;
    case "collectors":
      return <CollectorsPage />;
    case "settings":
      return <SettingsPage />;
    case "audit":
      return <AuditPage />;
    default:
      return <Overview />;
  }
}

function Sidebar({ route, onPalette }: { route: Route; onPalette: () => void }) {
  const { investigations, openNewInvestigation, theme, setTheme } = useApp();
  const nav: { route: Route; label: string; icon: string }[] = [
    { route: { page: "overview" }, label: "Overview", icon: "overview" },
    { route: { page: "collectors" }, label: "Collectors", icon: "collectors" },
    { route: { page: "audit" }, label: "Audit log", icon: "audit" },
    { route: { page: "settings" }, label: "Settings", icon: "settings" },
  ];
  const resolvedDark = document.documentElement.dataset.theme === "dark";
  return (
    <nav aria-label="Main" className="flex w-60 shrink-0 flex-col border-r border-line bg-panel">
      <a href={href({ page: "overview" })} className="flex items-center gap-2.5 px-4 py-3.5">
        <LogoMark size={34} />
        <Wordmark />
      </a>
      <div className="px-3">
        <button onClick={onPalette} className="flex w-full items-center gap-2 rounded border border-line bg-bg px-2.5 py-1.5 text-muted hover:border-accent/50">
          <Icon name="search" size={14} />
          <span className="flex-1 text-left">Search or run…</span>
          <Kbd>Ctrl K</Kbd>
        </button>
      </div>
      <ul className="mt-3 space-y-0.5 px-2">
        {nav.map((item) => {
          const active = route.page === item.route.page;
          return (
            <li key={item.label}>
              <a href={href(item.route)} aria-current={active ? "page" : undefined}
                className={`flex items-center gap-2.5 rounded px-2.5 py-1.5 ${active ? "bg-accent/15 text-fg" : "text-muted hover:bg-raised hover:text-fg"}`}>
                <Icon name={item.icon} />
                {item.label}
              </a>
            </li>
          );
        })}
      </ul>
      <div className="mt-5 flex items-center justify-between px-4">
        <span className="label">Investigations</span>
        <button className="text-muted hover:text-accent" onClick={openNewInvestigation} title="New investigation (Ctrl+Alt+N)" aria-label="New investigation">
          <Icon name="plus" />
        </button>
      </div>
      <ul className="mt-1 flex-1 space-y-0.5 overflow-auto px-2 pb-2">
        {investigations.length === 0 && <li className="px-2.5 py-1 text-muted">None yet</li>}
        {investigations.map((inv) => {
          const active = route.page === "investigation" && route.id === inv.id;
          return (
            <li key={inv.id}>
              <a href={href({ page: "investigation", id: inv.id, tab: "entities" })}
                className={`block truncate rounded px-2.5 py-1 ${active ? "bg-accent/15 text-fg" : "text-muted hover:bg-raised hover:text-fg"}`}
                title={inv.name}>
                {inv.name}
              </a>
            </li>
          );
        })}
      </ul>
      <div className="flex items-center justify-between border-t border-line px-4 py-2 text-xxs text-muted">
        <span>Local only · no telemetry</span>
        <button title="Toggle theme" aria-label="Toggle theme" className="hover:text-fg"
          onClick={() => setTheme(resolvedDark ? "light" : "dark")}>
          <Icon name={resolvedDark ? "sun" : "moon"} size={15} />
        </button>
      </div>
      <span className="sr-only">Current theme setting: {theme}</span>
    </nav>
  );
}

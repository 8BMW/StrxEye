import { useEffect, useMemo, useRef, useState } from "react";
import { Icon, Kbd } from "./ui";

export interface Command {
  id: string;
  label: string;
  hint?: string;
  run: () => void;
}

export function filterCommands(commands: Command[], query: string): Command[] {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return commands;
  return commands.filter((c) => {
    const hay = `${c.label} ${c.hint ?? ""}`.toLowerCase();
    return terms.every((t) => hay.includes(t));
  });
}

export function CommandPalette({ commands, onClose }: { commands: Command[]; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const results = useMemo(() => filterCommands(commands, query).slice(0, 50), [commands, query]);

  useEffect(() => input.current?.focus(), []);
  useEffect(() => setIndex(0), [query]);

  const run = (cmd: Command | undefined) => {
    if (!cmd) return;
    onClose();
    cmd.run();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 pt-[12vh]" onMouseDown={onClose}>
      <div role="dialog" aria-label="Command palette" className="card w-full max-w-xl shadow-2xl" onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 border-b border-line px-3">
          <Icon name="search" className="text-muted" />
          <input ref={input} value={query} onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command or investigation name"
            aria-label="Command" aria-controls="palette-results"
            className="w-full bg-transparent py-3 outline-none placeholder:text-muted/70"
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setIndex((i) => Math.min(i + 1, results.length - 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setIndex((i) => Math.max(i - 1, 0)); }
              else if (e.key === "Enter") { e.preventDefault(); run(results[index]); }
              else if (e.key === "Escape") onClose();
            }} />
          <Kbd>Esc</Kbd>
        </div>
        <ul id="palette-results" role="listbox" className="max-h-80 overflow-auto py-1">
          {results.length === 0 && <li className="px-4 py-3 text-muted">No matching commands</li>}
          {results.map((cmd, i) => (
            <li key={cmd.id} role="option" aria-selected={i === index}
              onMouseEnter={() => setIndex(i)} onClick={() => run(cmd)}
              className={`flex cursor-pointer items-center justify-between px-4 py-2 ${i === index ? "bg-accent/15" : ""}`}>
              <span className="truncate">{cmd.label}</span>
              {cmd.hint && <span className="ml-3 shrink-0 font-mono text-xxs text-muted">{cmd.hint}</span>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

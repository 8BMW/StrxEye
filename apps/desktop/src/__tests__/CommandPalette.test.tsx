import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CommandPalette, filterCommands, type Command } from "../components/CommandPalette";

afterEach(cleanup);

const commands = (spy = vi.fn()): Command[] => [
  { id: "a", label: "New investigation", run: spy },
  { id: "b", label: "Go to Settings", run: spy },
  { id: "c", label: "Open: Phishing case", hint: "abc123", run: spy },
];

describe("filterCommands", () => {
  it("matches all terms in any order, including hints", () => {
    expect(filterCommands(commands(), "case phish").map((c) => c.id)).toEqual(["c"]);
    expect(filterCommands(commands(), "abc1").map((c) => c.id)).toEqual(["c"]);
    expect(filterCommands(commands(), "")).toHaveLength(3);
  });
});

describe("CommandPalette", () => {
  it("runs the highlighted command with the keyboard", () => {
    const run = vi.fn();
    const onClose = vi.fn();
    render(<CommandPalette commands={commands(run)} onClose={onClose} />);
    const input = screen.getByRole("textbox", { name: "Command" });
    fireEvent.change(input, { target: { value: "settings" } });
    expect(screen.getAllByRole("option")).toHaveLength(1);
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onClose).toHaveBeenCalled();
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("closes on Escape", () => {
    const onClose = vi.fn();
    render(<CommandPalette commands={commands()} onClose={onClose} />);
    fireEvent.keyDown(screen.getByRole("textbox", { name: "Command" }), { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });
});

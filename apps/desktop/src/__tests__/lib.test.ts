import { describe, expect, it } from "vitest";
import { formatTime, formatValue, guessTargetType, href, parseRoute } from "../lib";

describe("routing", () => {
  it("round-trips investigation routes", () => {
    const route = { page: "investigation" as const, id: "abc123", tab: "graph" as const, entity: 42 };
    expect(parseRoute(href(route))).toEqual(route);
  });

  it("falls back to sensible defaults", () => {
    expect(parseRoute("")).toEqual({ page: "overview" });
    expect(parseRoute("#/inv/abc/unknown-tab")).toEqual({ page: "investigation", id: "abc", tab: "collect", entity: undefined });
    expect(parseRoute("#/nonsense")).toEqual({ page: "overview" });
    expect(parseRoute("#/settings")).toEqual({ page: "settings" });
  });
});

describe("guessTargetType", () => {
  it.each([
    ["example.com", "domain"],
    ["1.1.1.1", "ip"],
    ["2606:4700::1111", "ip"],
    ["AS13335", "asn"],
    ["https://example.com/x", "url"],
    ["d41d8cd98f00b204e9800998ecf8427e", "hash"],
    ["not a target", null],
  ])("%s -> %s", (input, expected) => {
    expect(guessTargetType(input)).toBe(expected);
  });
});

describe("formatting", () => {
  it("formats UTC timestamps", () => {
    expect(formatTime("2025-01-02T03:04:05+00:00")).toBe("2025-01-02 03:04:05 UTC");
    expect(formatTime(null)).toBe("—");
  });

  it("formats structured values without empty fields", () => {
    expect(formatValue({ host: "mx.example.com", preference: 10, extra: null })).toBe("host: mx.example.com  ·  preference: 10");
    expect(formatValue(["a", "b"])).toBe("a, b");
    expect(formatValue(true)).toBe("true");
  });
});

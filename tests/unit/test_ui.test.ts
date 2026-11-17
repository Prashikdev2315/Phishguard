import { describe, expect, it } from "vitest";
import { formatHost, REASON_TEXT } from "../../extension/src/lib/ui";
import { canAllowlist } from "../../extension/src/lib/allowlist";
import { normalize } from "../../extension/src/lib/normalize";

describe("Chunk 10 UI helpers", () => {
  it("formats Unicode hosts with their ASCII form", () => {
    expect(formatHost("例え.テスト", "xn--r8jz45g.xn--zckzah")).toContain("xn--r8jz45g");
  });
  it("provides safe plain-language reason text", () => {
    expect(REASON_TEXT["R-01"]).toContain("IP host");
    expect(Object.keys(REASON_TEXT)).toHaveLength(12);
  });
  it("rejects multi-tenant hosting root while allowing tenant domains", () => {
    expect(canAllowlist("github.io", normalize("github.io"))).toBe(false);
    expect(canAllowlist("my-tenant.github.io", normalize("my-tenant.github.io"))).toBe(true);
  });
});

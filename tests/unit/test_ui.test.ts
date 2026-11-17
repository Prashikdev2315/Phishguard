import { describe, expect, it } from "vitest";
import { formatHost, REASON_TEXT } from "../../extension/src/lib/ui";

describe("Chunk 10 UI helpers", () => {
  it("formats Unicode hosts with their ASCII form", () => {
    expect(formatHost("例え.テスト", "xn--r8jz45g.xn--zckzah")).toContain("xn--r8jz45g");
  });
  it("provides safe plain-language reason text", () => {
    expect(REASON_TEXT["R-01"]).toContain("IP host");
    expect(Object.keys(REASON_TEXT)).toHaveLength(12);
  });
});

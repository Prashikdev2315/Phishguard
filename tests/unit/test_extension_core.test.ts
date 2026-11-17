import { describe, expect, it } from "vitest";
import { cacheTtl } from "../../extension/src/lib/cache";
import { isHostingDomain } from "../../extension/src/lib/allowlist";
import { normalize } from "../../extension/src/lib/normalize";

describe("Chunk 9 extension core contracts", () => {
  it("uses the frozen cache TTLs", () => {
    expect(cacheTtl("Safe")).toBe(86_400_000);
    expect(cacheTtl("Suspicious")).toBe(21_600_000);
    expect(cacheTtl("High-Risk")).toBe(3_600_000);
  });
  it("rejects hosting roots while permitting tenant registrable domains", () => {
    expect(isHostingDomain("github.io")).toBe(true);
    expect(isHostingDomain(normalize("trusted.github.io").registrable_domain)).toBe(false);
  });
});

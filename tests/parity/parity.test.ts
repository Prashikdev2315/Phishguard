import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { FEATURE_NAMES, extractVector } from "../../extension/src/lib/features";
import { loadModel, predictRisk } from "../../extension/src/lib/model";
import { normalize } from "../../extension/src/lib/normalize";

const root = resolve(import.meta.dirname, "../..");

describe("Chunk 8 TypeScript parity", () => {
  it("normalizes frozen contract examples", () => {
    expect(normalize(" Example.COM:80/a/../login?utm_source=x#frag")).toMatchObject({
      error: null,
      normalized: "http://example.com/login?utm_source=x#frag",
      cache_key: "http://example.com/login",
      registrable_domain: "example.com",
    });
    expect(normalize("https://user.github.io/account").registrable_domain).toBe("user.github.io");
    expect(normalize("https://192.168.1.1/login").is_ip_host).toBe(true);
    expect(normalize("https://example.com/a b").error).toBe("whitespace_inside");
  });

  it("produces the frozen 50-feature vector", () => {
    const vector = extractVector("https://login.example.com/account/verify");
    expect(FEATURE_NAMES).toHaveLength(50);
    expect(vector).toBeInstanceOf(Float32Array);
    expect(vector).toHaveLength(50);
    expect([...vector].every(Number.isFinite)).toBe(true);
  });

  it("loads PGM1 and returns bounded risk", () => {
    const bytes = readFileSync(resolve(root, "extension/public/model.bin"));
    const model = loadModel(bytes);
    expect(model.trees).toHaveLength(200);
    const verdict = predictRisk(model, extractVector("https://example.com/"));
    expect(verdict.risk).toBeGreaterThanOrEqual(0);
    expect(verdict.risk).toBeLessThanOrEqual(100);
    expect(["Safe", "Suspicious", "High-Risk"]).toContain(verdict.band);
  });
});

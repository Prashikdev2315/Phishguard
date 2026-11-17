import type { CacheEntry, RiskBand } from "./types";
import { getCache, setCache, type StoredCache } from "./storage";

const TTL: Record<RiskBand, number> = { Safe: 86_400_000, Suspicious: 21_600_000, "High-Risk": 3_600_000 };
const CAP = 2000;
const encoder = new TextEncoder();

export async function hashCacheKey(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}
export function cacheTtl(band: RiskBand): number { return TTL[band]; }

export async function readCache(cacheKey: string, modelVersion: string, now = Date.now()): Promise<CacheEntry | null> {
  const key = await hashCacheKey(cacheKey);
  const cache = await getCache();
  const entry = cache[key];
  if (!entry || entry.modelVersion !== modelVersion || now - entry.timestamp >= TTL[entry.band]) {
    if (entry) { delete cache[key]; await setCache(cache); }
    return null;
  }
  entry.timestamp = now;
  await setCache(cache);
  return entry;
}
export async function writeCache(cacheKey: string, entry: CacheEntry): Promise<string> {
  const key = await hashCacheKey(cacheKey);
  const cache: StoredCache = await getCache();
  cache[key] = entry;
  const keys = Object.keys(cache);
  if (keys.length > CAP) {
    keys.sort((a, b) => cache[a].timestamp - cache[b].timestamp);
    for (const oldKey of keys.slice(0, keys.length - CAP)) delete cache[oldKey];
  }
  await setCache(cache);
  return key;
}
export async function clearCache(): Promise<void> { await setCache({}); }
export async function clearCacheForModel(modelVersion: string): Promise<void> {
  const cache = await getCache();
  for (const [key, value] of Object.entries(cache)) if (value.modelVersion !== modelVersion) delete cache[key];
  await setCache(cache);
}
export async function sweepCache(now = Date.now()): Promise<void> {
  const cache = await getCache();
  for (const [key, entry] of Object.entries(cache)) {
    if (now - entry.timestamp >= TTL[entry.band]) delete cache[key];
  }
  await setCache(cache);
}

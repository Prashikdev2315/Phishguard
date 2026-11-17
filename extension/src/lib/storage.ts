import { DEFAULT_SETTINGS, type CacheEntry, type HistoryEntry, type PendingBlock, type Settings } from "./types";

declare const chrome: any;
export type StoredCache = Record<string, CacheEntry>;

const localGet = async <T>(key: string, fallback: T): Promise<T> => {
  const result = await chrome.storage.local.get(key);
  return (result[key] as T | undefined) ?? fallback;
};
const localSet = (value: Record<string, unknown>) => chrome.storage.local.set(value);
const sessionGet = async <T>(key: string, fallback: T): Promise<T> => {
  const result = await chrome.storage.session.get(key);
  return (result[key] as T | undefined) ?? fallback;
};

export async function getSettings(): Promise<Settings> { return localGet("settings", DEFAULT_SETTINGS); }
export async function setSettings(settings: Settings): Promise<void> { await localSet({ settings }); }
export async function getUserAllowlist(): Promise<string[]> { return localGet("userAllowlist", []); }
export async function setUserAllowlist(userAllowlist: string[]): Promise<void> { await localSet({ userAllowlist }); }
export async function getCache(): Promise<StoredCache> { return localGet("cache", {}); }
export async function setCache(cache: StoredCache): Promise<void> { await localSet({ cache }); }
export async function getHistory(): Promise<HistoryEntry[]> { return localGet("history", []); }
export async function setHistory(history: HistoryEntry[]): Promise<void> { await localSet({ history }); }
export async function getCounters(): Promise<{ scans: number; blocks: number; warnings: number; overrides: number }> {
  return localGet("counters", { scans: 0, blocks: 0, warnings: 0, overrides: 0 });
}
export async function setCounters(counters: { scans: number; blocks: number; warnings: number; overrides: number }): Promise<void> {
  await localSet({ counters });
}
export async function setPending(token: string, value: PendingBlock): Promise<void> {
  await chrome.storage.session.set({ [`pending:${token}`]: value });
}
export async function getPending(token: string): Promise<PendingBlock | null> {
  const result = await chrome.storage.session.get(`pending:${token}`);
  return result[`pending:${token}`] ?? null;
}
export async function removePending(token: string): Promise<void> { await chrome.storage.session.remove(`pending:${token}`); }
export async function getOverrides(): Promise<Record<string, number>> { return sessionGet("overrides", {}); }
export async function setOverrides(overrides: Record<string, number>): Promise<void> { await chrome.storage.session.set({ overrides }); }
export async function getTabState(): Promise<Record<string, { token: string; lastVerdict: any; url: string }>> {
  return sessionGet("tabState", {});
}
export async function setTabState(tabState: Record<string, { token: string; lastVerdict: any; url: string }>): Promise<void> {
  await chrome.storage.session.set({ tabState });
}

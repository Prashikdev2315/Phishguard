import { addUserAllowed, isDefaultAllowed, isUserAllowed } from "./allowlist";
import { hashCacheKey, readCache, writeCache } from "./cache";
import { extractFeatures, extractVector } from "./features";
import { loadModel, predictRisk, type ExportedModel } from "./model";
import { normalize } from "./normalize";
import { getSettings, getCounters, setCounters, getHistory, setHistory, getOverrides } from "./storage";
import type { HistoryEntry, RiskVerdict } from "./types";

declare const chrome: any;
const MODEL_URL = "public/model.bin";
let modelPromise: Promise<ExportedModel> | null = null;
const modelVersion = () => "pg-model-1.0.0";

export async function getModel(): Promise<ExportedModel> {
  if (!modelPromise) modelPromise = fetch(chrome.runtime.getURL(MODEL_URL)).then(response => {
    if (!response.ok) throw new Error("model_corrupt");
    return response.arrayBuffer();
  }).then(loadModel);
  return modelPromise;
}
const setBadge = (tabId: number, verdict: RiskVerdict | null, error = false) => {
  const text = error ? "?" : verdict?.band === "Safe" ? "OK" : "!";
  const color = error ? "#6b7280" : verdict?.band === "Safe" ? "#10b981" : verdict?.band === "Suspicious" ? "#f59e0b" : "#ef4444";
  return Promise.all([chrome.action.setBadgeText({ tabId, text }), chrome.action.setBadgeBackgroundColor({ tabId, color })]);
};
async function record(host: string, verdict: RiskVerdict, action: HistoryEntry["action"]): Promise<void> {
  const history = (await getHistory()).filter(item => Date.now() - item.time < 30 * 86_400_000);
  history.push({ time: Date.now(), host, band: verdict.band, risk: verdict.risk, action });
  await setHistory(history.slice(-500));
}
export async function scanUrl(url: string): Promise<{ verdict: RiskVerdict; normalized: ReturnType<typeof normalize>; cacheKeyHash?: string }> {
  const normalized = normalize(url);
  if (normalized.error) throw new Error(normalized.error);
  const settings = await getSettings();
  const model = await getModel();
  if (isDefaultAllowed(normalized) || await isUserAllowed(normalized)) {
    const verdict: RiskVerdict = { risk: 0, probability: 0, band: "Safe", reasons: [] };
    return { verdict, normalized };
  }
  const overrides = await getOverrides();
  const overrideKey = await hashCacheKey(normalized.cache_key);
  if (overrides[overrideKey] && overrides[overrideKey] > Date.now()) {
    const verdict: RiskVerdict = { risk: 0, probability: 0, band: "Safe", reasons: [] };
    return { verdict, normalized, cacheKeyHash: overrideKey };
  }
  const cached = await readCache(normalized.cache_key, modelVersion());
  if (cached) return { verdict: { risk: cached.risk, probability: cached.risk / 100, band: cached.band, reasons: cached.reasons }, normalized };
  const features = extractFeatures(url);
  const verdict = predictRisk(model, extractVector(url));
  verdict.reasons = (await import("./reasons")).reasonCodes(verdict.risk, features, normalized);
  const cacheKeyHash = await writeCache(normalized.cache_key, { risk: verdict.risk, band: verdict.band, reasons: verdict.reasons, modelVersion: modelVersion(), timestamp: Date.now() });
  const counters = await getCounters();
  counters.scans++;
  await setCounters(counters);
  void settings;
  return { verdict, normalized, cacheKeyHash };
}
export async function handleNavigation(tabId: number, url: string): Promise<void> {
  if (!/^https?:/i.test(url)) return;
  try {
    const result = await scanUrl(url);
    await setBadge(tabId, result.verdict);
    await record(result.normalized.display_host, result.verdict, result.verdict.band === "High-Risk" ? "block" : result.verdict.band === "Suspicious" ? "warn" : "allow");
    const settings = await getSettings();
    if (result.verdict.band === "High-Risk" && settings.enforcementMode === "block") {
      const token = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, "0")).join("");
      await chrome.storage.session.set({ [`pending:${token}`]: { host: result.normalized.puny_host, displayHost: result.normalized.display_host, risk: result.verdict.risk, band: result.verdict.band, reasons: result.verdict.reasons, modelVersion: modelVersion(), url, cacheKeyHash: result.cacheKeyHash } });
      await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`src/pages/warning.html?token=${token}`) });
    }
  } catch (error) {
    await setBadge(tabId, null, true);
    const settings = await getSettings();
    if (settings.failureMode === "closed") await chrome.tabs.update(tabId, { url: chrome.runtime.getURL("src/pages/warning.html?failure=1") });
  }
}

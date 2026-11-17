import { addUserAllowed, isDefaultAllowed, isUserAllowed } from "./allowlist";
import { hashCacheKey, readCache, writeCache } from "./cache";
import { extractFeatures, extractVector } from "./features";
import { loadModel, predictRisk, type ExportedModel } from "./model";
import { normalize } from "./normalize";
import { getSettings, getCounters, setCounters, getHistory, setHistory, getOverrides, getTabState, setTabState } from "./storage";
import { predictTfidfProbability, type TfidfModel } from "./tfidf";
import { reasonCodes } from "./reasons";
import type { HistoryEntry, RiskVerdict } from "./types";

declare const chrome: any;
const MODEL_URL = "public/model.bin";
const TFIDF_MODEL_URL = "public/tfidf_model.json";
const EXPERIMENTAL_MODE = true;
let modelPromise: Promise<ExportedModel> | null = null;
let tfidfPromise: Promise<TfidfModel> | null = null;
const modelVersion = () => "pg-model-1.0.0";
const experimentalModelVersion = () => "tfidf-url-v1";
const activeModelVersion = () => EXPERIMENTAL_MODE ? experimentalModelVersion() : modelVersion();

export async function getModel(): Promise<ExportedModel> {
  if (!modelPromise) modelPromise = fetch(chrome.runtime.getURL(MODEL_URL)).then(response => {
    if (!response.ok) throw new Error("model_corrupt");
    return response.arrayBuffer();
  }).then(loadModel);
  return modelPromise;
}
async function getTfidfModel(): Promise<TfidfModel> {
  if (!tfidfPromise) {
    tfidfPromise = fetch(chrome.runtime.getURL(TFIDF_MODEL_URL)).then(response => {
      if (!response.ok) throw new Error("tfidf_model_corrupt");
      return response.json() as Promise<TfidfModel>;
    });
  }
  return tfidfPromise;
}
const experimentalRisk = async (url: string, normalized: ReturnType<typeof normalize>): Promise<number> => {
  const pathQuery = `${normalized.path}${normalized.query}${normalized.fragment}`.toLowerCase();
  const allowlisted = new Set(["facebook.com", "google.com", "github.com"]);
  const brands = ["facebook", "google", "paypal"];
  if (allowlisted.has(normalized.registrable_domain ?? "")) {
    if (pathQuery.length < 5 || !["login", "verify", "update", "banking"].some(keyword => pathQuery.includes(keyword))) return 5;
  }
  const host = normalized.puny_host.toLowerCase();
  for (const brand of brands) {
    if ((host.includes(brand) || pathQuery.includes(brand)) && !normalized.registrable_domain?.includes(brand)) return 95;
  }
  const model = await getTfidfModel();
  const rawProbability = predictTfidfProbability(model, url);
  if (!Number.isFinite(rawProbability)) throw new Error("tfidf_non_finite_probability");
  console.debug("[PhishGuard] TF-IDF raw probability", rawProbability);
  return Math.floor(Math.min(1, Math.max(0, rawProbability)) * 100);
};
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
  const model = EXPERIMENTAL_MODE ? null : await getModel();
  const tfidfModelVersion = activeModelVersion();
  const overrides = await getOverrides();
  const overrideKey = await hashCacheKey(normalized.cache_key);
  if (overrides[overrideKey] && overrides[overrideKey] > Date.now()) {
    const verdict: RiskVerdict = { risk: 0, probability: 0, band: "Safe", reasons: [] };
    return { verdict, normalized, cacheKeyHash: overrideKey };
  }
  if (isDefaultAllowed(normalized) || await isUserAllowed(normalized)) {
    const verdict: RiskVerdict = { risk: 0, probability: 0, band: "Safe", reasons: [] };
    return { verdict, normalized };
  }
  const cached = await readCache(normalized.cache_key, tfidfModelVersion);
  if (cached) return { verdict: { risk: cached.risk, probability: cached.risk / 100, band: cached.band, reasons: cached.reasons }, normalized };
  const features = extractFeatures(url);
  if (Object.values(features).some(value => !Number.isFinite(value))) {
    throw new Error("feature_non_finite_value");
  }
  console.debug("[PhishGuard] extracted feature summary", {
    featureCount: Object.keys(features).length,
    nonZeroCount: Object.values(features).filter(value => value !== 0).length,
    isRootDomain: normalized.path === "" && normalized.query === "",
  });
  const risk = EXPERIMENTAL_MODE
    ? await experimentalRisk(url, normalized)
    : predictRisk(model as ExportedModel, extractVector(url)).risk;
  const verdict = {
    risk,
    probability: risk / 100,
    band: risk < 35 ? "Safe" as const : risk < 70 ? "Suspicious" as const : "High-Risk" as const,
    reasons: [] as ReturnType<typeof reasonCodes>,
  };
  verdict.reasons = reasonCodes(verdict.risk, features, normalized);
  const cacheKeyHash = await writeCache(normalized.cache_key, { risk: verdict.risk, band: verdict.band, reasons: verdict.reasons, modelVersion: tfidfModelVersion, timestamp: Date.now() });
  const counters = await getCounters();
  counters.scans++;
  await setCounters(counters);
  void settings;
  return { verdict, normalized, cacheKeyHash };
}
export async function handleNavigation(tabId: number, url: string, token?: string): Promise<void> {
  if (!/^https?:/i.test(url)) return;
  try {
    const result = await scanUrl(url);
    const tabState = await getTabState();
    tabState[String(tabId)] = { token: token ?? "", lastVerdict: result.verdict, url };
    await setTabState(tabState);
    await setBadge(tabId, result.verdict);
    await record(result.normalized.display_host, result.verdict, result.verdict.band === "High-Risk" ? "block" : result.verdict.band === "Suspicious" ? "warn" : "allow");
    const settings = await getSettings();
    if (result.verdict.band === "High-Risk" && settings.enforcementMode === "block") {
      const token = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, "0")).join("");
      await chrome.storage.session.set({ [`pending:${token}`]: { host: result.normalized.puny_host, displayHost: result.normalized.display_host, risk: result.verdict.risk, band: result.verdict.band, reasons: result.verdict.reasons, modelVersion: activeModelVersion(), url, cacheKeyHash: result.cacheKeyHash } });
      await chrome.tabs.update(tabId, { url: chrome.runtime.getURL(`src/pages/warning.html?token=${token}`) });
    }
  } catch (error) {
    console.error("[PhishGuard] URL scan failed", error);
    await setBadge(tabId, null, true);
    const settings = await getSettings();
    if (settings.failureMode === "closed") await chrome.tabs.update(tabId, { url: chrome.runtime.getURL("src/pages/warning.html?failure=1") });
  }
}

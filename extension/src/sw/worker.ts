import { addUserAllowed } from "../lib/allowlist";
import { clearCache, sweepCache } from "../lib/cache";
import { handleNavigation } from "../lib/pipeline";
import {
  getCounters, getHistory, getPending, getSettings, getTabState, getUserAllowlist,
  removePending, setCounters, setHistory, setOverrides, setSettings, setTabState,
} from "../lib/storage";
import { DEFAULT_SETTINGS, type Settings } from "../lib/types";
import { normalize } from "../lib/normalize";

declare const chrome: any;
const tokens = new Map<number, string>();
const makeToken = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, "0")).join("");
const senderIsInternal = (sender: any) => sender?.id === chrome.runtime.id;
const supported = (url: string) => /^https?:/i.test(url) && !/(localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(url);

chrome.webNavigation.onBeforeNavigate.addListener((details: any) => {
  if (details.frameId !== 0 || !supported(details.url)) return;
  const token = makeToken();
  tokens.set(details.tabId, token);
  void handleNavigation(details.tabId, details.url, token);
});

chrome.runtime.onMessage.addListener((message: any, sender: any, sendResponse: (value: unknown) => void) => {
  if (!senderIsInternal(sender)) return;
  (async () => {
    switch (message?.type) {
      case "GET_TAB_STATUS": {
        const state = await getTabState();
        let tabId = message.tabId ?? sender.tab?.id;
        if (tabId === undefined) {
          try {
            const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
            tabId = tabs[0]?.id;
          } catch { /* ignore */ }
        }
        let tab = tabId !== undefined ? state[String(tabId)] : undefined;
        if (!tab?.lastVerdict) {
          const entries = Object.values(state) as Array<{ token: string; lastVerdict: any; url: string }>;
          if (entries.length > 0) tab = entries[entries.length - 1];
        }
        if (!tab?.lastVerdict) { sendResponse(null); break; }
        let host = "";
        try { host = new URL(tab.url).hostname; } catch { /* non-web tab */ }
        sendResponse({ ...tab.lastVerdict, host });
        break;
      }
      case "GET_SETTINGS": sendResponse(await getSettings()); break;
      case "GET_OPTIONS_DATA": sendResponse({ settings: await getSettings(), allowlist: await getUserAllowlist(), history: await getHistory(), counters: await getCounters() }); break;
      case "GET_BLOCK_DETAILS": sendResponse(message.token ? await getPending(message.token) : null); break;
      case "GO_BACK": {
        if (message.token) await removePending(message.token);
        if (sender.tab?.id !== undefined) await chrome.tabs.goBack(sender.tab.id).catch(() => chrome.tabs.update(sender.tab.id, { url: "chrome://newtab/" }));
        sendResponse({ ok: true }); break;
      }
      case "PROCEED_OVERRIDE": {
        const pending = message.token ? await getPending(message.token) : null;
        if (!pending) { sendResponse({ ok: false }); break; }
        const normalized = normalize(pending.url);
        const overrides = await (await import("../lib/storage")).getOverrides();
        const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalized.cache_key));
        const key = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
        overrides[key] = Date.now() + 30 * 60 * 1000;
        await setOverrides(overrides);
        const counters = await getCounters(); counters.overrides++; await setCounters(counters);
        await removePending(message.token);
        if (sender.tab?.id !== undefined) await chrome.tabs.update(sender.tab.id, { url: pending.url });
        sendResponse({ ok: true }); break;
      }
      case "TRUST_DOMAIN": {
        const normalized = normalize(String(message.host ?? ""));
        sendResponse({ ok: !normalized.error && await addUserAllowed(normalized.puny_host, normalized) }); break;
      }
      case "REMOVE_DOMAIN": {
        const domains = (await getUserAllowlist()).filter(domain => domain !== String(message.host ?? ""));
        await (await import("../lib/storage")).setUserAllowlist(domains);
        sendResponse({ ok: true }); break;
      }
      case "UPDATE_SETTINGS": {
        const current = await getSettings();
        const candidate = { ...current, ...(message.settings ?? {}) } as Settings;
        if (!["block", "warn_only"].includes(candidate.enforcementMode) || !["open", "closed"].includes(candidate.failureMode) || typeof candidate.bannerEnabled !== "boolean") throw new Error("invalid_settings");
        await setSettings(candidate); sendResponse({ ok: true }); break;
      }
      case "CLEAR_DATA":
        if (message.scope === "cache" || message.scope === "all") await clearCache();
        if (message.scope === "history" || message.scope === "all") await setHistory([]);
        if (message.scope === "all") await chrome.storage.local.clear();
        sendResponse({ ok: true }); break;
      default: sendResponse({ ok: false });
    }
  })().catch(error => sendResponse({ ok: false, error: String(error.message ?? error) }));
  return true;
});

chrome.alarms.onAlarm.addListener(async (alarm: any) => {
  if (alarm.name === "purge-history") {
    const history = (await getHistory()).filter(item => Date.now() - item.time < 30 * 86_400_000);
    await setHistory(history.slice(-500));
  }
  if (alarm.name === "sweep-cache") await sweepCache();
});
chrome.runtime.onInstalled.addListener(async (details: any) => {
  if (details.reason === "install") await chrome.tabs.create({ url: chrome.runtime.getURL("src/pages/first_run.html") });
  await chrome.alarms.create("purge-history", { periodInMinutes: 1440 });
  await chrome.alarms.create("sweep-cache", { periodInMinutes: 60 });
});

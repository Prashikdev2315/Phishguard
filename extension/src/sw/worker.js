// PhishGuard — bare service worker (Chunk 1 spike scaffold)
// This file is the minimum needed for the race harness spike (FR-09 / M0).
// Full pipeline is wired in Chunk 9 (Extension core).

"use strict";

// ── constants ───────────────────────────────────────────────────────────────
const EXT_VERSION   = chrome.runtime.getManifest().version;
const MODEL_VERSION = "pg-model-unset";   // replaced at export time (Chunk 7)

// ── state ───────────────────────────────────────────────────────────────────
// Per-PRD §8.3: per-tab token lives in storage.session.
// Here we use a plain Map (module scope) for the spike only;
// Chunk 9 moves this into storage.session for SW-restart safety.
const tabTokens = new Map();   // tabId → token string

// ── helpers ─────────────────────────────────────────────────────────────────
function makeToken() {
  // 16 hex bytes, crypto-random
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, "0")).join("");
}

function isScannableUrl(url) {
  if (!url) return false;
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// ── navigation listener (registered synchronously at top level) ─────────────
// PRD §4: webNavigation.onBeforeNavigate, frameId 0 only.
chrome.webNavigation.onBeforeNavigate.addListener(details => {
  if (details.frameId !== 0) return;          // subframes ignored (FR-01)
  if (!isScannableUrl(details.url)) return;   // restricted schemes ignored (FR-01)

  const token = makeToken();
  tabTokens.set(details.tabId, token);

  // SPIKE STUB: in the real pipeline (Chunk 9) this calls
  // normalize → feature-extract → model → classify → act.
  // For the race-harness spike we immediately signal "pending" so the
  // harness can measure whether tabs.update fires before the target commits.
  _spikeAct(details.tabId, details.url, token);
});

// ── spike stub action ────────────────────────────────────────────────────────
// In production this is replaced by the real verdict dispatcher in Chunk 9.
// For the spike we always redirect to the warning page so the harness can
// measure the race (FR-09, E2E-10).
async function _spikeAct(tabId, url, token) {
  // Store the pending details so warning.html can retrieve them.
  await chrome.storage.session.set({
    [`pending:${token}`]: {
      host: (() => { try { return new URL(url).hostname; } catch { return url; } })(),
      risk: 99,         // spike: treat every URL as High-Risk for race measurement
      band: "high-risk",
      reasons: ["SPIKE — race harness, not a real verdict"],
      modelVersion: MODEL_VERSION,
    }
  });

  // Redirect before target commits (FR-09).
  const warningUrl =
    chrome.runtime.getURL("src/pages/warning.html") + `?token=${token}`;
  chrome.tabs.update(tabId, { url: warningUrl });
}

// ── message handler (stub) ───────────────────────────────────────────────────
// Full message dispatch is in Chunk 9. Only GET_BLOCK_DETAILS is needed
// by warning.html during the spike.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // PRD §8.4: validate sender
  if (sender.id !== chrome.runtime.id) return;

  if (msg.type === "GET_BLOCK_DETAILS" && msg.token) {
    chrome.storage.session.get(`pending:${msg.token}`).then(result => {
      sendResponse(result[`pending:${msg.token}`] ?? null);
    });
    return true; // keep channel open for async response
  }
});

// ── install / update lifecycle ───────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(details => {
  if (details.reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL("src/pages/first_run.html") });
  }
  // "update" case: Chunk 10 adds the What's new note.
});

console.log(`[PhishGuard] service worker loaded — ext ${EXT_VERSION} model ${MODEL_VERSION}`);

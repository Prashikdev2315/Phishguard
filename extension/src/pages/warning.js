// warning.js — spike stub for the interstitial page (Chunk 1)
// All text inserted via textContent — never innerHTML (SEC-05).
"use strict";

(async () => {
  const params = new URLSearchParams(location.search);
  const token  = params.get("token");

  // ── fetch verdict from worker ──────────────────────────────────────────
  let details = null;
  if (token) {
    details = await new Promise(resolve => {
      chrome.runtime.sendMessage({ type: "GET_BLOCK_DETAILS", token }, resolve);
    });
  }

  // ── populate host display ──────────────────────────────────────────────
  const hostEl = document.getElementById("host-display");
  if (details?.host) {
    hostEl.textContent = `Real address: ${details.host}`;
  } else {
    hostEl.textContent = "(host unavailable)";
  }

  // ── populate reasons ───────────────────────────────────────────────────
  const reasonsEl = document.getElementById("reasons");
  const reasons   = details?.reasons ?? ["No reason data available"];
  for (const r of reasons) {
    const li = document.createElement("li");
    li.textContent = r;   // textContent only — never innerHTML
    reasonsEl.appendChild(li);
  }

  // ── Go back ────────────────────────────────────────────────────────────
  document.getElementById("btn-back").addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "GO_BACK", token }, () => {});
  });

  // ── Proceed-anyway flow (PRD FR-10) ───────────────────────────────────
  // Requires: disclosure click → checkbox tick → 1 s delay → trusted click
  let proceedEnabled = false;
  let proceedTimer   = null;

  document.getElementById("btn-proceed-toggle").addEventListener("click", e => {
    if (!e.isTrusted) return;             // reject scripted clicks (SEC-03)
    document.getElementById("proceed-section").style.display = "block";
    e.currentTarget.style.display = "none";
  });

  document.getElementById("risk-check").addEventListener("change", e => {
    if (!e.isTrusted) return;
    const btn = document.getElementById("btn-proceed");
    if (e.target.checked) {
      // 1-second delay before the button becomes clickable (FR-10)
      proceedTimer = setTimeout(() => {
        btn.disabled = false;
        proceedEnabled = true;
      }, 1000);
    } else {
      clearTimeout(proceedTimer);
      btn.disabled = true;
      proceedEnabled = false;
    }
  });

  document.getElementById("btn-proceed").addEventListener("click", e => {
    if (!e.isTrusted) return;             // reject scripted clicks (SEC-03)
    if (!proceedEnabled) return;
    chrome.runtime.sendMessage({ type: "PROCEED_OVERRIDE", token }, () => {});
  });
})();

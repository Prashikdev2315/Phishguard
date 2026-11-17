"use strict";
(() => {
  const $ = id => document.getElementById(id);
  const send = (type, payload = {}) => new Promise(resolve => chrome.runtime.sendMessage({ type, ...payload }, resolve));
  function render(data) {
    for (const input of document.querySelectorAll("input[name=enforcement]")) input.checked = input.value === data.settings.enforcementMode;
    for (const input of document.querySelectorAll("input[name=failure]")) input.checked = input.value === data.settings.failureMode;
    $("banner").checked = Boolean(data.settings.bannerEnabled);
    $("counters").textContent = `Scans: ${data.counters.scans} · Blocks: ${data.counters.blocks} · Warnings: ${data.counters.warnings} · Overrides: ${data.counters.overrides}`;
    const list = $("allowlist"); list.replaceChildren();
    for (const host of data.allowlist) { const li = document.createElement("li"); li.textContent = host; const button = document.createElement("button"); button.type = "button"; button.textContent = "Remove"; button.addEventListener("click", async () => { await send("REMOVE_DOMAIN", { host }); load(); }); li.append(" ", button); list.appendChild(li); }
    const body = $("history"); body.replaceChildren();
    for (const item of data.history.slice().reverse()) { const row = document.createElement("tr"); for (const value of [item.host, item.band, item.risk, item.action, new Date(item.time).toLocaleString()]) { const cell = document.createElement("td"); cell.textContent = String(value); row.appendChild(cell); } body.appendChild(row); }
  }
  async function load() { const data = await send("GET_OPTIONS_DATA"); if (data) render(data); }
  async function save() { const enforcementMode = document.querySelector("input[name=enforcement]:checked").value; const failureMode = document.querySelector("input[name=failure]:checked").value; await send("UPDATE_SETTINGS", { settings: { enforcementMode, failureMode, bannerEnabled: $("banner").checked } }); $("save-status").textContent = "Saved."; }
  document.querySelectorAll("input[name=enforcement], input[name=failure], #banner").forEach(input => input.addEventListener("change", save));
  $("allow-form").addEventListener("submit", async event => { event.preventDefault(); const host = $("allow-host").value.trim(); const result = await send("TRUST_DOMAIN", { host }); $("save-status").textContent = result?.ok ? "Domain added." : "That domain cannot be allowlisted."; if (result?.ok) { $("allow-host").value = ""; load(); } });
  for (const [id, scope] of [["clear-cache", "cache"], ["clear-history", "history"]]) $(id).addEventListener("click", async () => { await send("CLEAR_DATA", { scope }); load(); });
  $("clear-all").addEventListener("click", async () => { if (window.confirm("Reset all PhishGuard data?")) { await send("CLEAR_DATA", { scope: "all" }); load(); } });
  load();
})();

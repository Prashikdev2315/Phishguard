"use strict";
(() => {
  const $ = id => document.getElementById(id);
  let verdict = null;
  const reasonText = { "R-00": "The address has a suspicious overall risk pattern.", "R-01": "The address uses an IP host.", "R-02": "A brand appears outside its expected domain.", "R-03": "Sensitive action words appear repeatedly.", "R-04": "The address is unusually long.", "R-05": "The host has unusually deep subdomains.", "R-06": "The top-level domain is associated with elevated risk.", "R-07": "The host may use look-alike characters.", "R-08": "The host uses free or shared hosting.", "R-09": "The address embeds another URL.", "R-10": "Sensitive terms are used without HTTPS.", "R-11": "The host has high randomness." };
  function render(value) {
    verdict = value;
    const state = $("state"), icon = $("icon"), label = $("state-label");
    const band = value?.band ?? "Error";
    state.className = `state ${band.toLowerCase().replace("-", "-")}`;
    icon.textContent = band === "Safe" ? "✓" : band === "Suspicious" ? "!" : band === "High-Risk" ? "⚠" : "?";
    label.textContent = band === "Error" ? "Unscanned or unavailable" : band;
    $("score").textContent = value ? String(value.risk) : "—";
    $("host").textContent = value?.host || (value ? "Current tab" : "Checking this tab…");
    $("risk-meter").value = value?.risk ?? 0;
    const list = $("reasons"); list.replaceChildren();
    for (const reason of value?.reasons ?? []) { const li = document.createElement("li"); li.className = "reason"; li.textContent = reasonText[reason] ?? reason; list.appendChild(li); }
    if (!value) { const li = document.createElement("li"); li.className = "muted"; li.textContent = "This tab was not scanned."; list.appendChild(li); }
    $("trust").disabled = !value || value.band === "Safe";
  }
  chrome.runtime.sendMessage({ type: "GET_TAB_STATUS" }, render);
  $("settings").addEventListener("click", event => { event.preventDefault(); chrome.runtime.openOptionsPage(); });
  $("trust").addEventListener("click", () => chrome.runtime.sendMessage({ type: "TRUST_DOMAIN", host: verdict?.host || "" }, result => { if (result?.ok) { $("trust").textContent = "Trusted"; $("trust").disabled = true; $("toast").textContent = "Domain added to your allowlist."; } }));
  $("copy").addEventListener("click", async () => { const report = `PhishGuard\nRisk: ${verdict?.risk ?? "unscanned"}/100\nBand: ${verdict?.band ?? "Error"}\nReasons: ${(verdict?.reasons ?? []).join(", ") || "none"}\nTime: ${new Date().toISOString()}`; await navigator.clipboard.writeText(report); $("toast").textContent = "Copied!"; });
})();

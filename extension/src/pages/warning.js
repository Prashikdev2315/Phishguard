"use strict";
(() => {
  const params = new URLSearchParams(location.search), token = params.get("token");
  const $ = id => document.getElementById(id);
  const send = (type, payload = {}) => new Promise(resolve => chrome.runtime.sendMessage({ type, ...payload }, resolve));
  const reasons = { "R-00": "The address has a suspicious overall risk pattern.", "R-01": "The address uses an IP host.", "R-02": "A brand appears outside its expected domain.", "R-03": "Sensitive action words appear repeatedly.", "R-04": "The address is unusually long.", "R-05": "The host has unusually deep subdomains.", "R-06": "The top-level domain is associated with elevated risk.", "R-07": "The host may use look-alike characters.", "R-08": "The host uses free or shared hosting.", "R-09": "The address embeds another URL.", "R-10": "Sensitive terms are used without HTTPS.", "R-11": "The host has high randomness." };
  (async () => {
    if (params.get("failure") === "1") $("failure").classList.remove("hidden");
    const details = token ? await send("GET_BLOCK_DETAILS", { token }) : null;
    const formatHost = (d, p) => d && p && d !== p ? `${d} (${p})` : d || p;
    $("host-display").textContent = details?.displayHost ? formatHost(details.displayHost, details.host) : "Destination unavailable";
    const list = $("reasons"); list.replaceChildren();
    for (const reason of details?.reasons ?? []) { const item = document.createElement("li"); item.textContent = reasons[reason] ?? reason; list.appendChild(item); }
  })();
  $("btn-back").addEventListener("click", event => { if (event.isTrusted) send("GO_BACK", { token }); });
  $("btn-proceed-toggle").addEventListener("click", event => { if (!event.isTrusted) return; $("proceed-section").classList.remove("hidden"); $("btn-proceed-toggle").setAttribute("aria-expanded", "true"); });
  $("risk-check").addEventListener("change", event => { if (!event.isTrusted) return; const button = $("btn-proceed"); button.disabled = true; if (event.target.checked) setTimeout(() => { button.disabled = false; }, 1000); });
  $("btn-proceed").addEventListener("click", event => { if (event.isTrusted && !$("btn-proceed").disabled) send("PROCEED_OVERRIDE", { token }); });
})();

"use strict";
(() => {
  const send = (type, payload = {}) => new Promise(resolve => chrome.runtime.sendMessage({ type, ...payload }, resolve));
  document.getElementById("save").addEventListener("click", async () => {
    const enforcementMode = document.querySelector("input[name=enforcement]:checked").value;
    await send("UPDATE_SETTINGS", { settings: { enforcementMode } });
    document.getElementById("status").textContent = "✓ Settings saved! You're all set. You can close this tab and start browsing.";
  });
  document.getElementById("permission").addEventListener("click", async event => {
    if (!event.isTrusted) return;
    const granted = await chrome.permissions.request({ origins: ["<all_urls>"] });
    document.getElementById("status").textContent = granted ? "Optional banner permission enabled." : "Permission was not granted.";
  });
})();

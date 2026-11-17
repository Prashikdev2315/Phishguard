"use strict";
chrome.runtime.sendMessage({ type: "GET_TAB_STATUS" }, status => {
  const element = document.getElementById("status");
  if (!status) {
    element.textContent = "No scan available.";
    return;
  }
  element.textContent = `${status.band}: risk ${status.risk}/100`;
});

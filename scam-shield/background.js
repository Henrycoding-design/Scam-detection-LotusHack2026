chrome.storage.session
  .setAccessLevel({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" })
  .catch(() => {});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PAGE_LOADED" || message.type === "PAGE_UPDATED") {
    handleScan(message.context, sender.tab?.id);
  }
});

async function handleScan(context, tabId) {
  if (!context || typeof tabId !== "number") {
    return;
  }

  console.log("[ScamShield] Scanning:", context.url);
  console.log(`  -> ${context.links.length} links found`);
  console.log(`  -> ${context.visibleText.length} chars of text`);

  const mockRiskMap = {};
  context.links.forEach((link) => {
    mockRiskMap[link.href] = Math.floor(Math.random() * 101);
  });

  chrome.tabs
    .sendMessage(tabId, {
      type: "RISK_SCORES",
      riskMap: mockRiskMap,
    })
    .catch(() => {});
}

chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {});

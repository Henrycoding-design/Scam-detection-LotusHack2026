// background.js

// Allow content scripts to access session storage
chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS' });

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PAGE_LOADED" || message.type === "PAGE_UPDATED") {
    handleScan(message.context, sender.tab?.id);
  }
});

async function handleScan(context, tabId) {
  console.log("[ScamShield] Scanning:", context.url);
  console.log(`  → ${context.links.length} links found`);
  console.log(`  → ${context.visibleText.length} chars of text`);

  // STUB for Step 1 — in Step 2 this calls your scoring API
  const mockRiskMap = {};
  context.links.forEach((link) => {
    mockRiskMap[link.href] = 95; // force high risk for interception testing
  });

  // Send scores back to the content script
  if (tabId) {
    chrome.tabs.sendMessage(tabId, {
      type: "RISK_SCORES",
      riskMap: mockRiskMap,
    }).catch(() => {});
  }
}

// Open side panel when extension icon is clicked
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {});

// background.js

import { scorePageContext, scoreSingleLink } from "./scoring/heuristics.js";
import { getGeminiExplanation } from "./scoring/gemini.js";

// Allow content scripts to access session storage
chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS' });

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PAGE_LOADED" || message.type === "PAGE_UPDATED") {
    handleScan(message.context, sender.tab?.id);
  }
});

const API_URL = "https://ais-dev-fjmnvjtl3hg4ckuctxfs2e-625242509178.asia-southeast1.run.app"; // swap for deployed URL before demo

async function handleScan(context, tabId) {
  console.log("[ScamShield] Scanning:", context.url);

  let result;
  try {
    const res = await fetch(`${API_URL}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: context.url,
        links: context.links.map((l) => l.href),
        text: context.visibleText.slice(0, 3000),
        event: "load",
      }),
    });
    result = await res.json();
  } catch (err) {
    console.warn("[ScamShield] Backend unreachable, falling back to local scoring");
    // Fall back to local heuristics from Step 2 if backend is down
    const { scorePageContext } = await import("./scoring/heuristics.js");
    const { score, signals } = scorePageContext(context);
    result = {
      risk: score,
      verdict: score >= 70 ? "dangerous" : score >= 30 ? "suspicious" : "safe",
      reasons: signals.slice(0, 3).map((s) => s.reason),
      signals: signals,
    };
  }

  const pageScore = result.risk;
  const signals = result.signals || [];

  // Build per-link riskMap — score links from backend result
  // For hackathon simplicity: inherit the page score for all links
  const riskMap = {};
  context.links.forEach((l) => { riskMap[l.href] = pageScore; });

  console.log(`[ScamShield] Page score: ${pageScore}, verdict: ${result.verdict}`);

  // Send to content script
  if (tabId) {
    chrome.tabs.sendMessage(tabId, { type: "RISK_SCORES", riskMap }).catch(() => {});
    chrome.tabs.sendMessage(tabId, {
      type: "PAGE_VERDICT",
      score: pageScore,
      verdict: result.verdict,
      reasons: result.reasons,
    }).catch(() => {});
  }

  if (pageScore >= 30 && result.explanation && tabId) {
    chrome.tabs.sendMessage(tabId, {
      type: "PAGE_EXPLANATION",
      score: pageScore,
      explanation: result.explanation,
      signals: signals.slice(0, 3),
    }).catch(() => {});
  }

  // Store for sidebar
  chrome.storage.session.set({
    lastScan: {
      url: context.url,
      score: pageScore,
      verdict: result.verdict,
      reasons: result.reasons,
      explanation: result.explanation,
      timestamp: Date.now(),
    },
  });
}

// Open side panel when extension icon is clicked
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {});

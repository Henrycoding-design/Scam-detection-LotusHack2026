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

async function handleScan(context, tabId) {
  console.log("[ScamShield] Scanning:", context.url);

  // ── FAST LAYER: heuristic scoring ─────────────────────────────────
  const { score: pageScore, signals } = scorePageContext(context);

  // Score each link individually for the click interceptor
  const riskMap = {};
  const pageHostname = new URL(context.url).hostname;
  for (const link of context.links) {
    const { score } = scoreSingleLink(link.href, pageHostname);
    riskMap[link.href] = score;
  }

  console.log(`[ScamShield] Page score: ${pageScore}, top signal: ${signals[0]?.type}`);

  // Send scores to content script immediately (don't wait for Gemini)
  if (tabId) {
    chrome.tabs.sendMessage(tabId, { type: "RISK_SCORES", riskMap }).catch(() => {});
  }

  // ── LLM LAYER: Gemini explanation (async, non-blocking) ───────────
  if (pageScore >= 30) {
    const explanation = await getGeminiExplanation({
      url: context.url,
      score: pageScore,
      signals,
      visibleText: context.visibleText,
    });

    if (explanation && tabId) {
      chrome.tabs.sendMessage(tabId, {
        type: "PAGE_EXPLANATION",
        score: pageScore,
        explanation,
        signals: signals.slice(0, 3),
      }).catch(() => {});
    }

    // Persist to session storage for the side panel to read
    chrome.storage.session.set({
      lastScan: {
        url: context.url,
        score: pageScore,
        signals: signals.slice(0, 5),
        explanation,
        timestamp: Date.now(),
      },
    });
  }
}

// Open side panel when extension icon is clicked
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {});

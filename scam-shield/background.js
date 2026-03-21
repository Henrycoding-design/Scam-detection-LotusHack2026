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

  const { score, signals } = scorePageContext(context);
  const verdict = score >= 70 ? "dangerous" : score >= 30 ? "suspicious" : "safe";
  const reasons = signals
    .slice()
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((s) => s.reason);

  let explanation = null;
  if (score >= 20) {
    explanation = await getGeminiExplanation({
      url: context.url,
      score,
      signals,
      visibleText: context.visibleText.slice(0, 3000),
    });
  }

  const pageScore = score;

  const riskMap = {};
  context.links.forEach((l) => {
    const { score: linkScore } = scoreSingleLink(l.href, new URL(context.url).hostname);
    riskMap[l.href] = Math.max(linkScore, pageScore);
  });

  console.log(`[ScamShield] Page score: ${pageScore}, verdict: ${verdict}`);

  if (tabId) {
    chrome.tabs.sendMessage(tabId, { type: "RISK_SCORES", riskMap }).catch(() => {});
    chrome.tabs.sendMessage(tabId, {
      type: "PAGE_VERDICT",
      score: pageScore,
      verdict,
      reasons,
    }).catch(() => {});
  }

  if (pageScore >= 20 && explanation && tabId) {
    chrome.tabs.sendMessage(tabId, {
      type: "PAGE_EXPLANATION",
      score: pageScore,
      explanation,
      signals: signals.slice(0, 3),
    }).catch(() => {});
  }

  chrome.storage.session.set({
    lastScan: {
      url: context.url,
      score: pageScore,
      verdict,
      reasons,
      explanation,
      timestamp: Date.now(),
    },
  });
}

// Open side panel when extension icon is clicked
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {});

// background.js

import { scorePageContext, scoreSingleLink, buildTopReasons } from "./scoring/heuristics.js";
import { getGeminiExplanation, buildHeuristicFallbackExplanation } from "./scoring/gemini.js";
import { setScanState, setScanStatus } from "./state.js";

// Allow content scripts to access session storage
chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS' });

const pageScanCache = new Map();
const MAX_CACHE = 20;
const latestScanIds = new Map();

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PAGE_LOADED" || message.type === "PAGE_UPDATED") {
    handleScan(message.context, sender.tab?.id);
  }

  if (message.type === "OPEN_SIDE_PANEL" && sender.tab?.id) {
    chrome.sidePanel.open({ tabId: sender.tab.id }).catch(() => {});
  }
});

function normalizeUrl(url) {
  try {
    const parsed = new URL(url);
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return url;
  }
}

function buildPageKey(context) {
  const text = (context.visibleText || "").slice(0, 500);
  const links = (context.links || [])
    .slice(0, 20)
    .map((link) => normalizeUrl(link.href))
    .join("|");
  return `${normalizeUrl(context.url)}::${text}::${links}`;
}

function setCache(key, value) {
  if (pageScanCache.has(key)) {
    pageScanCache.delete(key);
  } else if (pageScanCache.size >= MAX_CACHE) {
    const firstKey = pageScanCache.keys().next().value;
    pageScanCache.delete(firstKey);
  }

  pageScanCache.set(key, value);
}

function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("AI timeout")), ms);
    promise
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch((error) => {
        clearTimeout(timer);
        reject(error);
      });
  });
}

function buildLinkRiskMap(context, pageScore) {
  const pageHost = new URL(context.url).hostname;
  const linkRiskMap = {};

  for (const link of context.links || []) {
    const normalizedHref = normalizeUrl(link.href);
    const { score: linkScore } = scoreSingleLink(normalizedHref, pageHost);
    linkRiskMap[normalizedHref] = linkScore;
  }

  return linkRiskMap;
}

async function safeSendMessage(tabId, payload) {
  if (!tabId) return;

  try {
    await chrome.tabs.sendMessage(tabId, payload);
  } catch (error) {
    console.warn("[ScamShield] Message delivery failed:", error);
  }
}

async function runHeuristicStage(context) {
  const cacheKey = buildPageKey(context);
  const cached = pageScanCache.get(cacheKey);
  if (cached) return { ...cached };

  const { score, signals } = scorePageContext(context);
  const verdict = score >= 70 ? "dangerous" : score >= 30 ? "suspicious" : "safe";
  const reasons = buildTopReasons(signals, 3);
  const linkRiskMap = buildLinkRiskMap(context, score);

  const result = {
    url: normalizeUrl(context.url),
    score,
    verdict,
    reasons,
    signals,
    linkRiskMap,
    explanation: null,
    aiStatus: score >= 20 ? "loading" : "skipped",
    timestamp: Date.now(),
  };

  setCache(cacheKey, result);
  return result;
}

async function runAiStage(heuristicResult, context) {
  try {
    const explanation = await withTimeout(
      getGeminiExplanation({
        url: heuristicResult.url,
        score: heuristicResult.score,
        signals: heuristicResult.signals,
        visibleText: (context.visibleText || "").slice(0, 3000),
      }),
      2500
    );

    return explanation || buildHeuristicFallbackExplanation(heuristicResult);
  } catch (error) {
    console.warn("[ScamShield] AI stage failed:", error);
    return buildHeuristicFallbackExplanation(heuristicResult);
  }
}

async function handleScan(context, tabId) {
  console.log("[ScamShield] Scanning:", context.url);

  const scanId = (latestScanIds.get(tabId) || 0) + 1;
  latestScanIds.set(tabId, scanId);

  await setScanStatus("scanning");

  const heuristicResult = await runHeuristicStage(context);

  await setScanState({
    lastPageResult: heuristicResult,
    lastScan: heuristicResult,
    linkRiskMap: heuristicResult.linkRiskMap,
    scanStatus: "heuristic_ready",
  });

  await safeSendMessage(tabId, {
    type: "LINK_RISK_MAP",
    linkRiskMap: heuristicResult.linkRiskMap,
  });
  await safeSendMessage(tabId, {
    type: "SCAN_STAGE_HEURISTIC",
    result: heuristicResult,
  });

  if (heuristicResult.aiStatus === "ready" && heuristicResult.explanation) {
    await setScanState({
      lastPageResult: heuristicResult,
      lastScan: heuristicResult,
      linkRiskMap: heuristicResult.linkRiskMap,
      scanStatus: "ai_ready",
    });
    await safeSendMessage(tabId, {
      type: "SCAN_STAGE_AI",
      result: heuristicResult,
    });
    return;
  }

  if (heuristicResult.score < 20) {
    await setScanState({
      lastPageResult: { ...heuristicResult, aiStatus: "skipped" },
      lastScan: { ...heuristicResult, aiStatus: "skipped" },
      scanStatus: "ai_ready",
    });
    return;
  }

  const explanation = await runAiStage(heuristicResult, context);

  if (scanId !== latestScanIds.get(tabId)) {
    return;
  }

  const finalResult = {
    ...heuristicResult,
    explanation,
    aiStatus: "ready",
    timestamp: Date.now(),
  };

  setCache(buildPageKey(context), finalResult);

  await setScanState({
    lastPageResult: finalResult,
    lastScan: finalResult,
    linkRiskMap: finalResult.linkRiskMap,
    scanStatus: "ai_ready",
  });

  await safeSendMessage(tabId, {
    type: "SCAN_STAGE_AI",
    result: finalResult,
  });
}

// Open side panel when extension icon is clicked
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {});

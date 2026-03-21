import { scorePageContext, scoreSingleLink, buildTopReasons } from "./scoring/heuristics.js";
import { getAiExplanation, buildHeuristicFallbackExplanation } from "./scoring/model.js";
import {
  setActiveTabId,
  setTabResult,
  getTabResult,
  removeTabResult,
  updateSidebar,
} from "./state.js";

chrome.storage.session.setAccessLevel({ accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS" });

const latestScanIds = new Map();
const RESTRICTED_SCHEMES = ["chrome:", "chrome-extension:", "edge:", "about:", "brave:", "opera:", "vivaldi:"];

function isRestrictedUrl(url) {
  if (!url) return true;
  try {
    return RESTRICTED_SCHEMES.includes(new URL(url).protocol);
  } catch {
    return true;
  }
}

function buildRestrictedResult(url) {
  return {
    url: url || "",
    score: 0,
    verdict: "not_scannable",
    reasons: [],
    signals: [],
    linkRiskMap: {},
    explanation: {
      verdict: "not_scannable",
      headline: "Browser internal page",
      reason: "This is a browser-internal page. ScamShield only scans regular web pages (http/https).",
      recommended_action: "No action needed — this page is managed by your browser.",
    },
    aiStatus: "skipped",
    timestamp: Date.now(),
  };
}

// ── Install / Startup: inject into pre-existing tabs ─────────────────

chrome.runtime.onInstalled.addListener(injectExistingTabs);
chrome.runtime.onStartup.addListener(injectExistingTabs);

async function injectExistingTabs() {
  const tabs = await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] });
  for (const tab of tabs) {
    ensureContentScripts(tab.id).catch(() => {});
  }
}

// ── Message Handlers ──────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type === "PAGE_LOADED" || message.type === "PAGE_UPDATED") {
    handleScan(message.context, sender.tab?.id);
  }

  if (message.type === "OPEN_SIDE_PANEL" && sender.tab?.id) {
    chrome.sidePanel.open({ tabId: sender.tab.id }).catch(() => {});
  }
});

// ── Tab Lifecycle ─────────────────────────────────────────────────────

chrome.tabs.onActivated.addListener(({ tabId }) => handleTabSwitch(tabId));

chrome.tabs.onRemoved.addListener((tabId) => {
  latestScanIds.delete(tabId);
  removeTabResult(tabId);
});

// ── Utilities ─────────────────────────────────────────────────────────

function normalizeUrl(url) {
  try {
    const parsed = new URL(url);
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return url;
  }
}

function buildLinkRiskMap(context) {
  const pageHost = new URL(context.url).hostname;
  const map = {};
  for (const link of context.links || []) {
    const href = normalizeUrl(link.href);
    map[href] = scoreSingleLink(href, pageHost).score;
  }
  return map;
}

// ── Content Script Management ─────────────────────────────────────────

async function contentScriptReady(tabId) {
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => !!window.ScamShieldScannerReady,
    });
    return result;
  } catch {
    return false;
  }
}

async function ensureContentScripts(tabId) {
  if (await contentScriptReady(tabId)) return;

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["content/ui.js", "content/scanner.js"],
    });
    await new Promise((r) => setTimeout(r, 500));
  } catch {
    // Restricted page (chrome://, chrome web store, etc.)
  }
}

// ── Tab Switch ────────────────────────────────────────────────────────

async function handleTabSwitch(tabId) {
  await setActiveTabId(tabId);

  const result = await getTabResult(tabId);
  if (result) {
    await updateSidebar(tabId, result, "ai_ready");
    safeSendMessage(tabId, { type: "LINK_RISK_MAP", linkRiskMap: result.linkRiskMap || {} });
    safeSendMessage(tabId, { type: "SCAN_STAGE_AI", result });
    return;
  }

  // Check if this is a browser-internal page that can't run content scripts
  try {
    const tab = await chrome.tabs.get(tabId);
    if (isRestrictedUrl(tab.url)) {
      const restricted = buildRestrictedResult(tab.url);
      await setTabResult(tabId, restricted);
      await updateSidebar(tabId, restricted, "ai_ready");
      return;
    }
  } catch {
    // Can't read tab info
  }

  // No cached result — show scanning state and ensure scripts are injected
  await updateSidebar(tabId, null, "scanning");
  ensureContentScripts(tabId).catch(() => {});
}

async function safeSendMessage(tabId, payload) {
  if (!tabId) return;
  try {
    await chrome.tabs.sendMessage(tabId, payload);
  } catch {
    // Tab may not have content script loaded yet
  }
}

// ── Scan Pipeline ─────────────────────────────────────────────────────

async function runHeuristicStage(context) {
  const { score, signals } = scorePageContext(context);
  const verdict = score >= 70 ? "dangerous" : score >= 30 ? "suspicious" : "safe";
  return {
    url: normalizeUrl(context.url),
    score,
    verdict,
    reasons: buildTopReasons(signals, 3),
    signals,
    linkRiskMap: buildLinkRiskMap(context),
    explanation: null,
    aiStatus: score >= 20 ? "loading" : "skipped",
    timestamp: Date.now(),
  };
}

async function runAiStage(heuristicResult, context) {
  try {
    return await getAiExplanation({
      url: heuristicResult.url,
      score: heuristicResult.score,
      signals: heuristicResult.signals,
      visibleText: (context.visibleText || "").slice(0, 3000),
    }) || buildHeuristicFallbackExplanation(heuristicResult);
  } catch {
    return buildHeuristicFallbackExplanation(heuristicResult);
  }
}

async function handleScan(context, tabId) {
  if (!tabId) return;

  const scanId = (latestScanIds.get(tabId) || 0) + 1;
  latestScanIds.set(tabId, scanId);

  // Heuristic stage — synchronous, always runs
  const heuristicResult = await runHeuristicStage(context);

  // Abort if a newer scan started while we were computing
  if (scanId !== latestScanIds.get(tabId)) return;

  await setTabResult(tabId, heuristicResult);
  await updateSidebar(tabId, heuristicResult, "heuristic_ready");
  await safeSendMessage(tabId, { type: "LINK_RISK_MAP", linkRiskMap: heuristicResult.linkRiskMap });
  await safeSendMessage(tabId, { type: "SCAN_STAGE_HEURISTIC", result: heuristicResult });

  // Skip AI for clearly safe pages
  if (heuristicResult.score < 20) {
    const safeResult = { ...heuristicResult, aiStatus: "skipped" };
    await setTabResult(tabId, safeResult);
    await updateSidebar(tabId, safeResult, "ai_ready");
    return;
  }

  // AI stage — async, may timeout
  const explanation = await runAiStage(heuristicResult, context);

  if (scanId !== latestScanIds.get(tabId)) return;

  const finalResult = { ...heuristicResult, explanation, aiStatus: "ready", timestamp: Date.now() };

  await setTabResult(tabId, finalResult);
  await updateSidebar(tabId, finalResult, "ai_ready");
  await safeSendMessage(tabId, { type: "SCAN_STAGE_AI", result: finalResult });
}

// ── Side Panel Behavior ───────────────────────────────────────────────

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

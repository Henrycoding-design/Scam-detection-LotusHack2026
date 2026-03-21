import { scorePageContext, scoreSingleLink, buildTopReasons } from "./scoring/heuristics.js";
import { getAiExplanation, buildFallbackExplanation } from "./scoring/model.js";
import { initBlocklist, checkBlocklist } from "./scoring/blocklist.js";
import { checkDomainAge } from "./scoring/domainAge.js";
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
    score: 100,
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

// ── Install / Startup ─────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async () => {
  initBlocklist();
  injectExistingTabs();
});
chrome.runtime.onStartup.addListener(() => {
  initBlocklist();
  injectExistingTabs();
});

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
    // Restricted page
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

  try {
    const tab = await chrome.tabs.get(tabId);
    if (isRestrictedUrl(tab.url)) {
      const restricted = buildRestrictedResult(tab.url);
      await setTabResult(tabId, restricted);
      await updateSidebar(tabId, restricted, "ai_ready");
      return;
    }
  } catch {}

  await updateSidebar(tabId, null, "scanning");
  ensureContentScripts(tabId).catch(() => {});
}

async function safeSendMessage(tabId, payload) {
  if (!tabId) return;
  try {
    await chrome.tabs.sendMessage(tabId, payload);
  } catch {}
}

// ── Scan Pipeline ─────────────────────────────────────────────────────

async function runHeuristicStage(context) {
  // Synchronous blocklist check
  let blocklistHit = null;
  try {
    blocklistHit = checkBlocklist(new URL(context.url).hostname);
  } catch {}

  // Enrich context with blocklist + DOM analysis
  const enriched = { ...context, blocklistHit, domainAgeSignal: null };

  const { score, signals, confidence } = scorePageContext(enriched);
  // score: 100 = safe, 0 = dangerous
  const verdict = score >= 70 ? "safe" : score >= 30 ? "suspicious" : "dangerous";

  return {
    url: normalizeUrl(context.url),
    score,
    verdict,
    confidence,
    reasons: buildTopReasons(signals, 3),
    signals,
    linkRiskMap: buildLinkRiskMap(context),
    explanation: null,
    aiStatus: score <= 70 ? "loading" : "skipped",
    timestamp: Date.now(),
  };
}

async function enrichDomainAge(context, heuristicResult, tabId) {
  try {
    const hostname = new URL(context.url).hostname;
    const ageResult = await checkDomainAge(hostname);
    if (!ageResult?.signal) return heuristicResult;

    // Re-score with domain age signal
    const enriched = {
      ...context,
      blocklistHit: heuristicResult.signals.find((s) => s.type.startsWith("blocklist_")) || null,
      domainAgeSignal: ageResult.signal,
    };
    const { score, signals, confidence } = scorePageContext(enriched);
    const verdict = score >= 70 ? "safe" : score >= 30 ? "suspicious" : "dangerous";

    return {
      ...heuristicResult,
      score,
      verdict,
      confidence,
      reasons: buildTopReasons(signals, 3),
      signals,
      linkRiskMap: heuristicResult.linkRiskMap,
    };
  } catch {
    return heuristicResult;
  }
}

async function runAiStage(heuristicResult, context) {
  try {
    return await getAiExplanation({
      url: heuristicResult.url,
      score: heuristicResult.score,
      signals: heuristicResult.signals,
      visibleText: (context.visibleText || "").slice(0, 3000),
    }) || buildFallbackExplanation(heuristicResult);
  } catch {
    return buildFallbackExplanation(heuristicResult);
  }
}

async function handleScan(context, tabId) {
  if (!tabId) return;

  const scanId = (latestScanIds.get(tabId) || 0) + 1;
  latestScanIds.set(tabId, scanId);

  // Stage 1: Heuristic + blocklist (instant)
  const heuristicResult = await runHeuristicStage(context);
  if (scanId !== latestScanIds.get(tabId)) return;

  await setTabResult(tabId, heuristicResult);
  await updateSidebar(tabId, heuristicResult, "heuristic_ready");
  await safeSendMessage(tabId, { type: "LINK_RISK_MAP", linkRiskMap: heuristicResult.linkRiskMap });
  await safeSendMessage(tabId, { type: "SCAN_STAGE_HEURISTIC", result: heuristicResult });

  // Skip AI for clearly safe pages
  if (heuristicResult.score >= 80) {
    const safeResult = { ...heuristicResult, aiStatus: "skipped" };
    await setTabResult(tabId, safeResult);
    await updateSidebar(tabId, safeResult, "ai_ready");
    return;
  }

  // Stage 2: Domain age (async, cached)
  const enrichedResult = await enrichDomainAge(context, heuristicResult, tabId);
  if (scanId !== latestScanIds.get(tabId)) return;

  // Stage 3: AI explanation
  const explanation = await runAiStage(enrichedResult, context);
  if (scanId !== latestScanIds.get(tabId)) return;

  const finalResult = { ...enrichedResult, explanation, aiStatus: "ready", timestamp: Date.now() };

  await setTabResult(tabId, finalResult);
  await updateSidebar(tabId, finalResult, "ai_ready");
  await safeSendMessage(tabId, { type: "SCAN_STAGE_AI", result: finalResult });
}

// ── Side Panel Behavior ───────────────────────────────────────────────

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

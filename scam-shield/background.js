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

function logStage(stage, payload = {}) {
  console.log(`[ScamShield][Stage] ${stage}`, payload);
}

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
  logStage("startup.inject_existing_tabs", { count: tabs.length });
  for (const tab of tabs) {
    ensureContentScripts(tab.id).catch(() => {});
  }
}

// ── Message Handlers ──────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender) => {
  logStage("message.received", {
    type: message.type,
    tabId: sender.tab?.id || null,
    url: message.context?.url || null,
  });

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
  logStage("tab.switch.start", { tabId });
  await setActiveTabId(tabId);

  const result = await getTabResult(tabId);
  if (result) {
    logStage("tab.switch.cache_hit", {
      tabId,
      url: result.url,
      score: result.score,
      verdict: result.verdict,
    });
    await updateSidebar(tabId, result, "ai_ready");
    safeSendMessage(tabId, { type: "LINK_RISK_MAP", linkRiskMap: result.linkRiskMap || {} });
    safeSendMessage(tabId, { type: "SCAN_STAGE_AI", result });
    return;
  }

  try {
    const tab = await chrome.tabs.get(tabId);
    if (isRestrictedUrl(tab.url)) {
      const restricted = buildRestrictedResult(tab.url);
      logStage("tab.switch.restricted_page", { tabId, url: tab.url });
      await setTabResult(tabId, restricted);
      await updateSidebar(tabId, restricted, "ai_ready");
      return;
    }
  } catch {}

  await updateSidebar(tabId, null, "scanning");
  logStage("tab.switch.no_cache", { tabId });
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
  logStage("heuristic.start", {
    url: context.url,
    title: context.title,
    linkCount: context.links?.length || 0,
    textLength: context.visibleText?.length || 0,
  });

  // Synchronous blocklist check
  let blocklistHit = null;
  try {
    blocklistHit = checkBlocklist(new URL(context.url).hostname);
    logStage("heuristic.blocklist_check", {
      url: context.url,
      hit: Boolean(blocklistHit),
      type: blocklistHit?.type || null,
      risk: blocklistHit?.risk || null,
    });
  } catch {}

  // Enrich context with blocklist + DOM analysis
  const enriched = { ...context, blocklistHit, domainAgeSignal: null };

  const { score, signals, confidence } = scorePageContext(enriched);
  // score: 100 = safe, 0 = dangerous
  const verdict = score >= 70 ? "safe" : score >= 30 ? "suspicious" : "dangerous";

  logStage("heuristic.complete", {
    url: context.url,
    score,
    verdict,
    confidence,
    signalCount: signals.length,
    topSignals: signals
      .slice()
      .sort((a, b) => b.risk - a.risk)
      .slice(0, 5)
      .map((s) => ({ type: s.type, risk: s.risk, category: s.category })),
  });

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

async function enrichDomainAge(context, heuristicResult) {
  try {
    logStage("domain_age.start", { url: context.url });
    const ageResult = await checkDomainAge(new URL(context.url).hostname);
    if (!ageResult?.signal) {
      logStage("domain_age.none", { url: context.url, ageDays: ageResult?.ageDays ?? null });
      return heuristicResult;
    }

    // Append domain age signal and re-score (lightweight — only one new signal)
    const signals = [...heuristicResult.signals, ageResult.signal];
    const { score } = scorePageContext({ ...context, domainAgeSignal: ageResult.signal, blocklistHit: null });
    const verdict = score >= 70 ? "safe" : score >= 30 ? "suspicious" : "dangerous";

    logStage("domain_age.complete", {
      url: context.url,
      ageDays: ageResult.ageDays,
      addedSignal: ageResult.signal.type,
      rescoredTo: score,
      verdict,
    });

    return { ...heuristicResult, score, verdict, reasons: buildTopReasons(signals, 3), signals };
  } catch (error) {
    logStage("domain_age.error", {
      url: context.url,
      error: error?.message || String(error),
    });
    return heuristicResult;
  }
}

async function runAiStage(heuristicResult, context) {
  try {
    logStage("ai.start", {
      url: heuristicResult.url,
      score: heuristicResult.score,
      verdict: heuristicResult.verdict,
      signalCount: heuristicResult.signals?.length || 0,
    });

    const explanation = await getAiExplanation({
      url: heuristicResult.url,
      score: heuristicResult.score,
      signals: heuristicResult.signals,
      visibleText: context.visibleText || "",
    });

    if (explanation) {
      logStage("ai.complete", {
        url: heuristicResult.url,
        headline: explanation.headline || null,
      });
      return explanation;
    }

    logStage("ai.fallback", {
      url: heuristicResult.url,
      reason: "provider returned null",
    });
    return buildFallbackExplanation(heuristicResult);
  } catch (error) {
    logStage("ai.error", {
      url: heuristicResult.url,
      error: error?.message || String(error),
    });
    return buildFallbackExplanation(heuristicResult);
  }
}

async function handleScan(context, tabId) {
  if (!tabId) return;

  const scanId = (latestScanIds.get(tabId) || 0) + 1;
  latestScanIds.set(tabId, scanId);
  logStage("scan.start", {
    tabId,
    scanId,
    url: context.url,
  });

  // Stage 1: Heuristic + blocklist (instant)
  const heuristicResult = await runHeuristicStage(context);
  if (scanId !== latestScanIds.get(tabId)) {
    logStage("scan.cancelled_after_heuristic", { tabId, scanId, url: context.url });
    return;
  }

  await setTabResult(tabId, heuristicResult);
  await updateSidebar(tabId, heuristicResult, "heuristic_ready");
  await safeSendMessage(tabId, { type: "LINK_RISK_MAP", linkRiskMap: heuristicResult.linkRiskMap });
  await safeSendMessage(tabId, { type: "SCAN_STAGE_HEURISTIC", result: heuristicResult });
  logStage("scan.heuristic_published", {
    tabId,
    scanId,
    score: heuristicResult.score,
    verdict: heuristicResult.verdict,
  });

  // Skip AI for clearly safe pages
  if (heuristicResult.score >= 80) {
    const safeResult = { ...heuristicResult, aiStatus: "skipped" };
    await setTabResult(tabId, safeResult);
    await updateSidebar(tabId, safeResult, "ai_ready");
    logStage("scan.ai_skipped", {
      tabId,
      scanId,
      score: heuristicResult.score,
      verdict: heuristicResult.verdict,
    });
    return;
  }

  // Stage 2: Domain age (async, cached)
  const enrichedResult = await enrichDomainAge(context, heuristicResult);
  if (scanId !== latestScanIds.get(tabId)) {
    logStage("scan.cancelled_after_domain_age", { tabId, scanId, url: context.url });
    return;
  }

  // Stage 3: AI explanation
  const explanation = await runAiStage(enrichedResult, context);
  if (scanId !== latestScanIds.get(tabId)) {
    logStage("scan.cancelled_after_ai", { tabId, scanId, url: context.url });
    return;
  }

  const finalResult = { ...enrichedResult, explanation, aiStatus: "ready", timestamp: Date.now() };

  await setTabResult(tabId, finalResult);
  await updateSidebar(tabId, finalResult, "ai_ready");
  await safeSendMessage(tabId, { type: "SCAN_STAGE_AI", result: finalResult });
  logStage("scan.complete", {
    tabId,
    scanId,
    url: finalResult.url,
    score: finalResult.score,
    verdict: finalResult.verdict,
    hasExplanation: Boolean(finalResult.explanation),
  });
}

// ── Side Panel Behavior ───────────────────────────────────────────────

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

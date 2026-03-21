// background.js

import { buildAnalysisPayload } from "./scoring/analysis.js";
import { scorePageContext, scoreSingleLink } from "./scoring/heuristics.js";
import { getOpenAIExplanation } from "./scoring/openai.js";

const DEFAULT_DEPENDENCIES = {
  chromeApi: globalThis.chrome,
  fetchImpl: globalThis.fetch,
  getExplanation: getOpenAIExplanation,
  now: () => Date.now(),
  explanationTimeoutMs: 4000,
  destinationTimeoutMs: 2000,
};
const pageScanState = new Map();

export function registerBackground() {
  const chromeApi = globalThis.chrome;
  if (!chromeApi?.runtime?.onMessage) {
    return;
  }

  chromeApi.storage.session.setAccessLevel({
    accessLevel: "TRUSTED_AND_UNTRUSTED_CONTEXTS",
  });

  chromeApi.runtime.onMessage.addListener((message, sender) => {
    handleRuntimeMessage(message, sender);
  });

  chromeApi.sidePanel
    .setPanelBehavior({ openPanelOnActionClick: true })
    .catch(() => {});
}

export function resetScanState() {
  pageScanState.clear();
}

export function handleRuntimeMessage(
  message,
  sender,
  dependencies = DEFAULT_DEPENDENCIES
) {
  const { chromeApi } = dependencies;

  if (message.type === "OPEN_SIDE_PANEL" && sender?.tab?.id) {
    chromeApi?.sidePanel?.open({ tabId: sender.tab.id }).catch(() => {});
    return;
  }

  if (message.type === "ANALYZE_LINK") {
    return handleAnalyzeLink(message, sender.tab?.id, dependencies);
  }

  if (message.type === "PAGE_LOADED" || message.type === "PAGE_UPDATED") {
    return handleScan(message.context, sender.tab?.id, dependencies, message.type);
  }
}

export async function handleScan(
  context,
  tabId,
  dependencies = DEFAULT_DEPENDENCIES,
  scanType = "PAGE_LOADED"
) {
  const { chromeApi, getExplanation, now, explanationTimeoutMs } = dependencies;

  console.log("[ScamShield] Scanning:", context.url);

  const { score: pageScore, signals } = scorePageContext(context);
  const riskMap = {};
  const pageHostname = new URL(context.url).hostname;
  for (const link of context.links) {
    const { score } = scoreSingleLink(link.href, pageHostname);
    riskMap[link.href] = score;
  }

  console.log(`[ScamShield] Page score: ${pageScore}, top signal: ${signals[0]?.type}`);

  sendTabMessage(chromeApi, tabId, { type: "RISK_SCORES", riskMap });

  const pageKey = getPageKey(tabId, context.url);
  const { pageState, shouldCallOpenAI } = getPageStateForScan(
    pageKey,
    pageScore,
    scanType
  );

  const immediateAnalysis = buildAnalysisPayload({
    subjectType: "page",
    url: context.url,
    score: pageScore,
    signals,
    aiStatus: pageScore >= 30 ? pageState.aiStatus : "skipped",
    explanation: pageScore >= 30 ? pageState.explanation : null,
  });

  sendTabMessage(chromeApi, tabId, {
    type: "PAGE_SCAN_RESULT",
    analysis: immediateAnalysis,
  });
  setSession(chromeApi, {
    lastScan: {
      ...immediateAnalysis,
      timestamp: now(),
    },
  });

  if (!shouldCallOpenAI) {
    return immediateAnalysis;
  }

  const explanation = await Promise.race([
    getExplanation({
      url: context.url,
      score: pageScore,
      signals,
      visibleText: context.visibleText,
      subjectType: "page",
      likelyScamType: immediateAnalysis.scamType,
    }),
    new Promise((resolve) => setTimeout(() => resolve(null), explanationTimeoutMs)),
  ]);
  const aiStatus = explanation ? "ready" : "unavailable";
  pageState.aiStatus = aiStatus;
  pageState.explanation = explanation;

  const finalAnalysis = buildAnalysisPayload({
    subjectType: "page",
    url: context.url,
    score: pageScore,
    signals,
    aiStatus,
    explanation,
  });

  sendTabMessage(chromeApi, tabId, {
    type: "PAGE_EXPLANATION",
    analysis: finalAnalysis,
  });
  setSession(chromeApi, {
    lastScan: {
      ...finalAnalysis,
      timestamp: now(),
    },
  });

  return finalAnalysis;
}

export async function handleAnalyzeLink(
  message,
  tabId,
  dependencies = DEFAULT_DEPENDENCIES
) {
  const {
    chromeApi,
    destinationTimeoutMs,
    explanationTimeoutMs,
    fetchImpl,
    getExplanation,
  } = dependencies;
  const href = message.link?.href || "";
  const pageHostname = safeHostname(message.pageContext?.url);
  const { score, signals } = scoreSingleLink(href, pageHostname);

  const immediateAnalysis = buildAnalysisPayload({
    subjectType: "link",
    url: href,
    score,
    signals,
    aiStatus: score >= 70 ? "pending" : "skipped",
  });

  sendTabMessage(chromeApi, tabId, {
    type: "LINK_ANALYSIS_RESULT",
    analysis: immediateAnalysis,
  });
  setSession(chromeApi, {
    lastLinkAnalysis: {
      ...immediateAnalysis,
      timestamp: dependencies.now(),
    },
  });

  if (score < 70) {
    return immediateAnalysis;
  }

  const destinationSummary = await fetchDestinationSummary(
    href,
    fetchImpl,
    destinationTimeoutMs
  );
  const linkVisibleText = buildLinkVisibleText(message, destinationSummary);
  const explanation = await Promise.race([
    getExplanation({
      url: href,
      score,
      signals,
      visibleText: linkVisibleText,
      subjectType: "link",
      destinationSummary,
      likelyScamType: immediateAnalysis.scamType,
    }),
    new Promise((resolve) => setTimeout(() => resolve(null), explanationTimeoutMs)),
  ]);
  const aiStatus = explanation ? "ready" : "unavailable";

  const finalAnalysis = buildAnalysisPayload({
    subjectType: "link",
    url: href,
    score,
    signals,
    aiStatus,
    explanation,
    destinationSummary,
  });

  sendTabMessage(chromeApi, tabId, {
    type: "LINK_ANALYSIS_RESULT",
    analysis: finalAnalysis,
  });
  setSession(chromeApi, {
    lastLinkAnalysis: {
      ...finalAnalysis,
      timestamp: dependencies.now(),
    },
  });

  return finalAnalysis;
}

export async function fetchDestinationSummary(
  url,
  fetchImpl = globalThis.fetch,
  timeoutMs = 2000
) {
  const startedAt = Date.now();

  try {
    const response = await fetchWithTimeout(
      fetchImpl,
      url,
      {
        headers: {
          "User-Agent": "Mozilla/5.0",
        },
      },
      timeoutMs
    );
    return summarizeDestinationResponse(response);
  } catch (error) {
    if (!looksLikeCorsError(error)) {
      return null;
    }

    const remaining = Math.max(0, timeoutMs - (Date.now() - startedAt));
    if (!remaining) {
      return null;
    }

    try {
      const fallbackResponse = await fetchWithTimeout(
        fetchImpl,
        url,
        { mode: "no-cors" },
        remaining
      );
      if (!fallbackResponse || fallbackResponse.type === "opaque") {
        return null;
      }
      return summarizeDestinationResponse(fallbackResponse);
    } catch {
      return null;
    }
  }
}

async function summarizeDestinationResponse(response) {
  if (!response || response.type === "opaque" || typeof response.text !== "function") {
    return null;
  }

  const contentType = response.headers?.get?.("content-type") || "";
  if (contentType && !contentType.includes("text/html")) {
    return null;
  }

  const html = await response.text();
  if (!html) {
    return null;
  }

  const title = matchTag(html, /<title[^>]*>([\s\S]*?)<\/title>/i);
  const description = matchTag(
    html,
    /<meta[^>]+(?:name|property)=["'](?:description|og:description)["'][^>]+content=["']([^"']+)["']/i
  );
  const bodyText = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 1200);

  return {
    title,
    description,
    snippet: bodyText,
  };
}

function getPageKey(tabId, url) {
  return `${tabId ?? "no-tab"}:${url}`;
}

function getPageStateForScan(pageKey, pageScore, scanType) {
  let pageState = pageScanState.get(pageKey);

  if (scanType === "PAGE_LOADED" || !pageState) {
    pageState = {
      initialEligible: pageScore >= 30,
      explanationRequested: false,
      aiStatus: pageScore >= 30 ? "pending" : "skipped",
      explanation: null,
    };
    pageScanState.set(pageKey, pageState);
  }

  if (pageScore < 30) {
    pageState.aiStatus = "skipped";
    pageState.explanation = null;
    return { pageState, shouldCallOpenAI: false };
  }

  if (!pageState.initialEligible) {
    return { pageState, shouldCallOpenAI: false };
  }

  if (!pageState.explanationRequested) {
    pageState.explanationRequested = true;
    pageState.aiStatus = "pending";
    return { pageState, shouldCallOpenAI: true };
  }

  return { pageState, shouldCallOpenAI: false };
}

async function fetchWithTimeout(fetchImpl, url, options, timeoutMs) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetchImpl(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

function buildLinkVisibleText(message, destinationSummary) {
  const pageSnippet = String(message.pageContext?.visibleText || "").slice(0, 500);
  return [
    `Link text: ${message.link?.text || "Unknown"}`,
    `Source page title: ${message.pageContext?.title || "Unknown"}`,
    destinationSummary?.title ? `Destination title: ${destinationSummary.title}` : "",
    destinationSummary?.description
      ? `Destination description: ${destinationSummary.description}`
      : "",
    destinationSummary?.snippet
      ? `Destination snippet: ${destinationSummary.snippet}`
      : "",
    pageSnippet ? `Source page snippet: ${pageSnippet}` : "",
  ]
    .filter(Boolean)
    .join("\n");
}

function looksLikeCorsError(error) {
  const message = error?.message || "";
  return error?.name === "TypeError" || /cors/i.test(message);
}

function matchTag(html, pattern) {
  const match = html.match(pattern);
  return match?.[1]?.replace(/\s+/g, " ").trim() || "";
}

function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function sendTabMessage(chromeApi, tabId, payload) {
  if (tabId && chromeApi?.tabs?.sendMessage) {
    chromeApi.tabs.sendMessage(tabId, payload).catch(() => {});
  }
}

function setSession(chromeApi, payload) {
  chromeApi?.storage?.session?.set(payload);
}

registerBackground();

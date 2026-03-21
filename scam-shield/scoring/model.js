const GEMINI_API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models";
const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";
const DEFAULT_PROVIDER = "auto";
const DEFAULT_GEMINI_MODEL = "gemini-2.5-flash-lite";
const DEFAULT_OPENROUTER_MODEL = "stepfun/step-3.5-flash:free";

let cachedLocalConfig = null;

function logDebug(label, payload = {}) {
  console.log(`[ScamShield][AI] ${label}`, payload);
}

async function getLocalAiConfig() {
  if (cachedLocalConfig) return cachedLocalConfig;

  try {
    const response = await fetch(chrome.runtime.getURL("config.local.json"), {
      cache: "no-store",
    });

    if (!response.ok) {
      cachedLocalConfig = {};
      return cachedLocalConfig;
    }

    cachedLocalConfig = await response.json();
    return cachedLocalConfig;
  } catch {
    cachedLocalConfig = {};
    return cachedLocalConfig;
  }
}

async function getAiConfig() {
  const stored = await chrome.storage.local.get([
    "aiProvider",
    "geminiApiKey",
    "geminiModel",
    "openrouterApiKey",
    "openrouterModel",
  ]);
  const local = await getLocalAiConfig();

  const provider = String(stored.aiProvider || local.aiProvider || DEFAULT_PROVIDER).trim() || DEFAULT_PROVIDER;
  const geminiApiKey = String(stored.geminiApiKey || local.geminiApiKey || "").trim();
  const geminiModel = String(stored.geminiModel || local.geminiModel || DEFAULT_GEMINI_MODEL).trim() || DEFAULT_GEMINI_MODEL;
  const openrouterApiKey = String(stored.openrouterApiKey || local.openrouterApiKey || "").trim();
  const openrouterModel = String(stored.openrouterModel || local.openrouterModel || DEFAULT_OPENROUTER_MODEL).trim() || DEFAULT_OPENROUTER_MODEL;

  return {
    provider,
    geminiApiKey,
    geminiModel,
    openrouterApiKey,
    openrouterModel,
  };
}

function buildSpecificAction({ verdict, reasons }) {
  if (reasons.some((reason) => /password|login|verify|identity|payment|bank/i.test(reason))) {
    return "Do not enter passwords, banking details, codes, or personal information here. Leave the page and sign in from the official website manually.";
  }

  return verdict === "dangerous"
    ? "Leave the page now, avoid clicking anything else, and do not download files or submit information."
    : "Pause before engaging, verify the domain through an official source, and only continue if you can confirm the site is legitimate.";
}

export function buildHeuristicFallbackExplanation({ verdict, reasons, score }) {
  const normalizedReasons = (reasons || []).map((reason) => typeof reason === "string" ? reason : reason.reason).filter(Boolean);
  return {
    verdict,
    adjusted_score: Number.isFinite(score) ? score : verdict === "dangerous" ? 80 : verdict === "suspicious" ? 45 : 10,
    validated: false,
    headline: verdict === "dangerous" ? "High-risk page detected" : verdict === "suspicious" ? "This page looks suspicious" : "Low risk page",
    reason: normalizedReasons.length > 0
      ? normalizedReasons.join(". ")
      : "Several scam signals were detected on this page.",
    recommended_action: buildSpecificAction({ verdict, reasons: normalizedReasons }),
    validation_notes: "Fallback explanation used because no AI provider returned a result.",
  };
}

function buildValidationPrompt({ url, score, signals, visibleText }) {
  const topSignals = (signals || [])
    .slice()
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 4)
    .map((signal) => `- ${signal.reason} (weight ${signal.weight})`)
    .join("\n");

  const textSnippet = (visibleText || "").slice(0, 1000);

  return `You are a cybersecurity assistant validating whether scam heuristics are actually correct.

URL: ${url}
Heuristic Score: ${score}/100

Detected signals:
${topSignals || "- None"}

Page text snippet:
"${textSnippet}"

Your job:
- Validate whether the warning signals are real or likely false positives.
- Treat trivial hostname variations like google.com and www.google.com as the same site.
- Downgrade benign CDN, asset, or common brand-owned subdomain cases.
- Only keep or raise the warning when the page still looks suspicious after validation.

Respond with JSON only:
{
  "verdict": "safe" | "suspicious" | "dangerous",
  "adjusted_score": 0-100 integer,
  "validated": true,
  "headline": "short risk summary",
  "reason": "clear explanation for a non-technical user",
  "recommended_action": "specific immediate next step",
  "validation_notes": "brief note saying what was confirmed, downgraded, or corrected"
}`;
}

function sanitizeAiExplanation(explanation, fallbackScore) {
  const adjustedScore = Number.isFinite(explanation?.adjusted_score)
    ? Math.max(0, Math.min(100, Math.round(explanation.adjusted_score)))
    : fallbackScore;

  const scoreVerdict = adjustedScore >= 70 ? "dangerous" : adjustedScore >= 30 ? "suspicious" : "safe";
  const verdict = ["safe", "suspicious", "dangerous"].includes(explanation?.verdict)
    ? explanation.verdict
    : scoreVerdict;

  return {
    verdict,
    adjusted_score: adjustedScore,
    validated: explanation?.validated !== false,
    headline: explanation?.headline || "AI validation completed",
    reason: explanation?.reason || "The page was reviewed by the AI validator.",
    recommended_action: explanation?.recommended_action || "Review the page carefully before continuing.",
    validation_notes: explanation?.validation_notes || "AI validation completed.",
  };
}

async function callGemini(config, payload) {
  const endpoint = `${GEMINI_API_ROOT}/${encodeURIComponent(config.geminiModel)}:generateContent`;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-goog-api-key": config.geminiApiKey,
    },
    body: JSON.stringify({
      contents: [{ parts: [{ text: payload.prompt }] }],
      generationConfig: {
        temperature: 0.1,
        responseMimeType: "application/json",
      },
    }),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    logDebug("Gemini request failed", {
      status: response.status,
      body,
      model: config.geminiModel,
    });
    return null;
  }

  const data = await response.json();
  const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
  const cleaned = rawText.replace(/```json|```/g, "").trim();
  return JSON.parse(cleaned);
}

async function callOpenRouter(config, payload) {
  const response = await fetch(OPENROUTER_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${config.openrouterApiKey}`,
      "HTTP-Referer": "https://github.com/Henrycoding-design/Scam-detection-LotusHack2026",
      "X-Title": "ScamShield",
    },
    body: JSON.stringify({
      model: config.openrouterModel,
      messages: [{ role: "user", content: payload.prompt }],
      temperature: 0.1,
    }),
  });

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    logDebug("OpenRouter request failed", {
      status: response.status,
      body,
      model: config.openrouterModel,
    });
    return null;
  }

  const data = await response.json();
  const rawText = data.choices?.[0]?.message?.content || "";
  const cleaned = rawText.replace(/```json|```/g, "").trim();
  return JSON.parse(cleaned);
}

function getProviderOrder(config) {
  if (config.provider === "gemini") return ["gemini"];
  if (config.provider === "openrouter") return ["openrouter"];

  const providers = [];
  if (config.geminiApiKey) providers.push("gemini");
  if (config.openrouterApiKey) providers.push("openrouter");
  return providers;
}

export async function getAiExplanation({ url, score, signals, visibleText }) {
  if (score < 20) return null;

  const config = await getAiConfig();
  const providers = getProviderOrder(config);
  if (providers.length === 0) {
    logDebug("No AI provider configured", {
      provider: config.provider,
    });
    return null;
  }

  const payload = {
    prompt: buildValidationPrompt({ url, score, signals, visibleText }),
  };

  for (const provider of providers) {
    try {
      logDebug("AI request starting", {
        provider,
        url,
        score,
      });

      const rawResult = provider === "gemini"
        ? await callGemini(config, payload)
        : await callOpenRouter(config, payload);

      if (rawResult) {
        const sanitized = sanitizeAiExplanation(rawResult, score);
        logDebug("AI response received", {
          provider,
          verdict: sanitized.verdict,
          adjustedScore: sanitized.adjusted_score,
        });
        return sanitized;
      }
    } catch (error) {
      logDebug("AI provider failed", {
        provider,
        error: error?.message || String(error),
      });
    }
  }

  return null;
}

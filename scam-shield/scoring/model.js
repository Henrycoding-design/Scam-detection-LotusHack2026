const GEMINI_API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models";
const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";
const DEFAULT_PROVIDER = "auto";
const DEFAULT_GEMINI_MODEL = "gemini-2.5-flash";
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
    logDebug("Loaded local config", {
      hasGeminiKey: Boolean(cachedLocalConfig.geminiApiKey),
      hasOpenRouterKey: Boolean(cachedLocalConfig.openrouterApiKey),
      provider: cachedLocalConfig.aiProvider || null,
    });
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

  const config = {
    provider: String(stored.aiProvider || local.aiProvider || DEFAULT_PROVIDER).trim() || DEFAULT_PROVIDER,
    geminiApiKey: String(stored.geminiApiKey || local.geminiApiKey || "").trim(),
    geminiModel: String(stored.geminiModel || local.geminiModel || DEFAULT_GEMINI_MODEL).trim() || DEFAULT_GEMINI_MODEL,
    openrouterApiKey: String(stored.openrouterApiKey || local.openrouterApiKey || "").trim(),
    openrouterModel: String(stored.openrouterModel || local.openrouterModel || DEFAULT_OPENROUTER_MODEL).trim() || DEFAULT_OPENROUTER_MODEL,
  };
  logDebug("Resolved AI config", {
    provider: config.provider,
    hasGeminiKey: Boolean(config.geminiApiKey),
    geminiModel: config.geminiModel,
    hasOpenRouterKey: Boolean(config.openrouterApiKey),
    openrouterModel: config.openrouterModel,
  });
  return config;
}

function getProviderOrder(config) {
  if (config.provider === "gemini") return ["gemini"];
  if (config.provider === "openrouter") return ["openrouter"];

  const order = [];
  if (config.geminiApiKey) order.push("gemini");
  if (config.openrouterApiKey) order.push("openrouter");
  logDebug("Provider order selected", {
    provider: config.provider,
    order,
  });
  return order;
}

export function buildFallbackExplanation({ score, signals }) {
  const topReasons = (signals || [])
    .slice()
    .sort((a, b) => b.risk - a.risk)
    .slice(0, 3);

  const reasonText = topReasons.length > 0
    ? topReasons.map((s) => s.reason).join(". ") + "."
    : "No specific threats detected.";

  const verdict = score >= 70 ? "safe" : score >= 30 ? "suspicious" : "dangerous";

  return {
    headline: verdict === "dangerous"
      ? "High-risk page detected"
      : verdict === "suspicious"
        ? "This page shows warning signs"
        : "This page appears safe",
    reason: reasonText,
    recommended_action: verdict === "dangerous"
      ? "Leave the page immediately and do not enter any information."
      : verdict === "suspicious"
        ? "Proceed with caution. Verify the URL and do not enter sensitive info."
        : "No immediate action needed.",
  };
}

function buildPrompt({ url, score, signals, visibleText }) {
  const signalDescriptions = (signals || [])
    .slice()
    .sort((a, b) => b.risk - a.risk)
    .slice(0, 5)
    .map((s) => `- [Risk ${s.risk}/100] ${s.reason}: ${s.detail || "No additional detail."}`)
    .join("\n");

  return `You are a cybersecurity analyst explaining findings to a non-technical user. You MUST base your explanation ONLY on the signals listed below. Do NOT invent new risks or reasons not listed.

URL: ${url}
Safety Score: ${score}/100 (100 = fully safe, 0 = extremely dangerous)

Detected signals (these are the ONLY risks — do not add any others):
${signalDescriptions || "No specific signals detected."}

Page text snippet:
"${visibleText || ""}"

Write a JSON object. The "reason" field MUST be a thorough explanation that helps a non-technical user understand the warning signals, how they work together, and how to verify legitimacy.

JSON only, no markdown:
{
  "headline": "...",
  "reason": "...",
  "recommended_action": "..."
}`;
}

function sanitizeExplanation(explanation) {
  return {
    headline: explanation?.headline || "AI analysis completed",
    reason: explanation?.reason || "The configured AI provider returned a response, but it did not include a detailed explanation.",
    recommended_action: explanation?.recommended_action || "Review the page carefully before continuing.",
  };
}

async function callGemini(config, prompt) {
  const endpoint = `${GEMINI_API_ROOT}/${encodeURIComponent(config.geminiModel)}:generateContent`;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-goog-api-key": config.geminiApiKey,
    },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
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
  return JSON.parse(rawText.replace(/```json|```/g, "").trim());
}

async function callOpenRouter(config, prompt) {
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
      messages: [{ role: "user", content: prompt }],
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
  return JSON.parse(rawText.replace(/```json|```/g, "").trim());
}

export async function getAiExplanation({ url, score, signals, visibleText }) {
  if (score >= 80) return null;

  const config = await getAiConfig();
  const providers = getProviderOrder(config);
  if (providers.length === 0) {
    logDebug("No AI provider configured", {
      provider: config.provider,
    });
    return null;
  }

  const prompt = buildPrompt({ url, score, signals, visibleText });

  for (const provider of providers) {
    try {
      logDebug("AI request starting", {
        provider,
        url,
        score,
      });

      const rawResult = provider === "gemini"
        ? await callGemini(config, prompt)
        : await callOpenRouter(config, prompt);

      if (rawResult) {
        logDebug("AI response received", {
          provider,
          headline: rawResult.headline || null,
        });
        return sanitizeExplanation(rawResult);
      }

      logDebug("AI provider returned empty result", {
        provider,
        url,
      });
    } catch (error) {
      logDebug("AI provider failed", {
        provider,
        error: error?.message || String(error),
      });
    }
  }

  logDebug("All AI providers failed or returned empty", {
    url,
    providers,
  });
  return null;
}

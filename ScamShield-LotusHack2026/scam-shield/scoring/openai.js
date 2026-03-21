// scoring/openai.js

// WARNING: Hardcoding API keys in a Chrome Extension is insecure for production.
// Anyone can inspect the extension files and steal the key.
// We are doing this TEMPORARILY for demo and debugging only.
const OPENAI_API_KEY = "OPENAI_API_KEY";
const OPENAI_MODEL = "gpt-5.4";
const OPENAI_URL = "https://api.openai.com/v1/responses";

export const EXPLANATION_SCHEMA = {
  type: "object",
  properties: {
    verdict: {
      type: "string",
      enum: ["dangerous", "suspicious", "safe"],
    },
    scam_type: {
      type: "string",
      minLength: 1,
      maxLength: 120,
    },
    headline: {
      type: "string",
      minLength: 1,
      maxLength: 120,
    },
    reason: {
      type: "string",
      minLength: 1,
      maxLength: 500,
    },
    risk_location: {
      type: "string",
      minLength: 1,
      maxLength: 320,
    },
    recommended_action: {
      type: "string",
      minLength: 1,
      maxLength: 240,
    },
    prevention_tips: {
      type: "array",
      minItems: 2,
      maxItems: 3,
      items: {
        type: "string",
        minLength: 1,
        maxLength: 180,
      },
    },
  },
  required: [
    "verdict",
    "scam_type",
    "headline",
    "reason",
    "risk_location",
    "recommended_action",
    "prevention_tips",
  ],
  additionalProperties: false,
};

export function buildOpenAIExplanationRequest({
  url,
  score,
  signals,
  visibleText,
  subjectType = "page",
  destinationSummary = null,
  likelyScamType = "",
}) {
  const sortedSignals = [...signals]
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((signal) => `- ${signal.reason}`)
    .join("\n");

  const textSnippet = String(visibleText || "").slice(0, 600);
  const riskBand = score >= 70 ? "DANGEROUS" : "SUSPICIOUS";
  const destinationContext = destinationSummary
    ? `
Fetched destination preview:
Title: ${destinationSummary.title || "Unknown"}
Description: ${destinationSummary.description || "None"}
Snippet: "${String(destinationSummary.snippet || "").slice(0, 600)}"`
    : `
Fetched destination preview:
Unavailable or unreadable; rely on URL, heuristics, and visible page text only.`;

  const input = `You are a cybersecurity assistant helping a non-technical person understand whether a page looks like a scam.

Analyze the page context below and return a plain-language explanation that matches the required JSON schema.

Subject Type: ${subjectType}
URL: ${url}
Risk Score: ${score}/100 (${riskBand})
Likely scam type from heuristics: ${likelyScamType || "Unknown"}

Top detected signals:
${sortedSignals || "- No major heuristic signals provided"}

Page text snippet:
"${textSnippet}"
${destinationContext}

Instructions:
- Explain the risk clearly and calmly.
- Name the likely scam type in scam_type.
- Keep the headline under 12 words.
- Mention only the strongest evidence shown above.
- Fill risk_location with where the scam is most likely happening (domain, login form, redirect, fake verification flow, etc.).
- prevention_tips must contain 2-3 short tips for avoiding this kind of scam in the future.
- Recommend one immediate next action.
- If the page does not look risky, verdict may be "safe".`;

  return {
    model: OPENAI_MODEL,
    store: false,
    reasoning: {
      effort: "low",
    },
    input,
    text: {
      format: {
        type: "json_schema",
        name: "scamshield_explanation",
        strict: true,
        schema: EXPLANATION_SCHEMA,
      },
    },
  };
}

export async function getOpenAIExplanation(context) {
  try {
    const response = await fetch(OPENAI_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${OPENAI_API_KEY}`,
      },
      body: JSON.stringify(buildOpenAIExplanationRequest(context)),
    });

    if (!response.ok) {
      console.warn("[ScamShield] OpenAI API error:", response.status);
      return null;
    }

    const data = await response.json();
    return normalizeExplanationResponse(data);
  } catch (err) {
    console.warn("[ScamShield] OpenAI parse error:", err);
    return null;
  }
}

function normalizeExplanationResponse(data) {
  const parsedExplanation = extractParsedExplanation(data);
  if (parsedExplanation) {
    return parsedExplanation;
  }

  const rawText = extractResponseText(data);
  if (!rawText) {
    return null;
  }

  try {
    const parsed = JSON.parse(stripMarkdownFences(rawText));
    return isValidExplanation(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function extractParsedExplanation(data) {
  const candidates = [
    data?.output_parsed,
    data?.parsed,
  ];

  if (Array.isArray(data?.output)) {
    for (const item of data.output) {
      candidates.push(item?.parsed);
      if (Array.isArray(item?.content)) {
        for (const content of item.content) {
          candidates.push(content?.parsed);
        }
      }
    }
  }

  return candidates.find(isValidExplanation) || null;
}

function extractResponseText(data) {
  const texts = [];

  if (typeof data?.output_text === "string") {
    texts.push(data.output_text);
  }

  if (Array.isArray(data?.output)) {
    for (const item of data.output) {
      if (typeof item?.text === "string") {
        texts.push(item.text);
      }
      if (typeof item?.output_text === "string") {
        texts.push(item.output_text);
      }
      if (Array.isArray(item?.content)) {
        for (const content of item.content) {
          if (typeof content?.text === "string") {
            texts.push(content.text);
          }
          if (typeof content?.output_text === "string") {
            texts.push(content.output_text);
          }
          if (typeof content?.value === "string") {
            texts.push(content.value);
          }
        }
      }
    }
  }

  return texts.find((text) => text.trim()) || "";
}

function stripMarkdownFences(text) {
  return text.replace(/```json|```/gi, "").trim();
}

function isValidExplanation(value) {
  return Boolean(
    value &&
      typeof value === "object" &&
      ["dangerous", "suspicious", "safe"].includes(value.verdict) &&
      typeof value.scam_type === "string" &&
      value.scam_type.trim() &&
      typeof value.headline === "string" &&
      value.headline.trim() &&
      typeof value.reason === "string" &&
      value.reason.trim() &&
      typeof value.risk_location === "string" &&
      value.risk_location.trim() &&
      typeof value.recommended_action === "string" &&
      value.recommended_action.trim() &&
      Array.isArray(value.prevention_tips) &&
      value.prevention_tips.length >= 2 &&
      value.prevention_tips.every(
        (tip) => typeof tip === "string" && tip.trim()
      )
  );
}

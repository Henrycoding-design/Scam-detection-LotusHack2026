// scoring/model.js — AI explanation via OpenRouter (free model)
// AI uses EXISTING signals only — no hallucinated reasons.

const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";

async function loadApiKey() {
  try {
    const { OPENROUTER_API_KEY } = await import("./config.js");
    return OPENROUTER_API_KEY;
  } catch {
    return null;
  }
}

export function buildFallbackExplanation({ score, signals }) {
  const topReasons = signals
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

export async function getAiExplanation({ url, score, signals, visibleText }) {
  // Don't waste API calls on clearly safe pages
  if (score >= 80) return null;

  const apiKey = await loadApiKey();
  if (!apiKey) return null;

  // Feed ONLY the existing signals to the AI
  const signalDescriptions = signals
    .slice()
    .sort((a, b) => b.risk - a.risk)
    .slice(0, 5)
    .map((s) => `- [Risk ${s.risk}/100] ${s.reason}: ${s.detail || "No additional detail."}`)
    .join("\n");

  const textSnippet = visibleText.slice(0, 800);

  const prompt = `You are a cybersecurity analyst explaining findings to a non-technical user. You MUST base your explanation ONLY on the signals listed below. Do NOT invent new risks or reasons not listed.

URL: ${url}
Safety Score: ${score}/100 (100 = fully safe, 0 = extremely dangerous)

Detected signals (these are the ONLY risks — do not add any others):
${signalDescriptions || "No specific signals detected."}

Page text snippet:
"${textSnippet}"

Write a JSON object with:
- "headline": Short summary (1 sentence) of the overall risk level
- "reason": Detailed explanation (3-6 sentences) that synthesizes the signals above into a coherent narrative. Explain what each signal means in plain English and what could happen if the user engages. Reference the specific signals listed above — do not fabricate new ones.
- "recommended_action": Specific steps the user should take right now

JSON only, no markdown:
{
  "headline": "...",
  "reason": "...",
  "recommended_action": "..."
}`;

  try {
    const response = await fetch(OPENROUTER_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
        "HTTP-Referer": "https://github.com/Henrycoding-design/Scam-detection-LotusHack2026",
      },
      body: JSON.stringify({
        model: "stepfun/step-3.5-flash:free",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.1,
        reasoning: { enabled: false },
      }),
    });

    if (!response.ok) {
      console.warn("[ScamShield] OpenRouter API error:", response.status);
      return null;
    }

    const data = await response.json();
    const rawText = data.choices?.[0]?.message?.content || "";

    const cleaned = rawText.replace(/```json|```/g, "").trim();
    return JSON.parse(cleaned);
  } catch (err) {
    console.warn("[ScamShield] AI parse error:", err);
    return null;
  }
}

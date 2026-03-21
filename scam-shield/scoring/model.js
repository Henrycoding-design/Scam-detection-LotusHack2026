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

  const textSnippet = visibleText;

  const prompt = `You are a cybersecurity analyst explaining findings to a non-technical user. You MUST base your explanation ONLY on the signals listed below. Do NOT invent new risks or reasons not listed.

URL: ${url}
Safety Score: ${score}/100 (100 = fully safe, 0 = extremely dangerous)

Detected signals (these are the ONLY risks — do not add any others):
${signalDescriptions || "No specific signals detected."}

Page text snippet:
"${textSnippet}"

Write a JSON object. The "reason" field MUST be a long, thorough analysis (15-25 sentences minimum) structured as follows:
1. Start with a plain-English summary of what was found and why it matters
2. For EACH signal listed above, write 3-4 sentences explaining: what it detected, why it's dangerous in this context, what a scammer would do with it, and a real-world example of how this technique is used
3. Explain the combined risk — how these signals together paint a picture of what the user is dealing with
4. End with specific verification steps the user can take to check if this is legitimate or a scam

Do NOT be brief. This is the most important analysis the user will read. Every signal deserves a full paragraph of explanation.

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

// scoring/gemini.js — now uses OpenRouter (free model) instead of paid Gemini

// You need a free OpenRouter API key from https://openrouter.ai/keys
// Free models like meta-llama/llama-3.1-8b-instruct:free require no credits.
const OPENROUTER_API_KEY = "sk-or-v1-YOUR_FREE_KEY_HERE";
const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";

export function buildHeuristicFallbackExplanation({ verdict, reasons }) {
  const reasonText = reasons.length > 0
    ? reasons.map(r => typeof r === "string" ? r : r.reason).join(". ")
    : "Several scam signals were detected on this page.";

  return {
    verdict,
    headline: verdict === "dangerous" ? "High-risk page detected" : "This page looks suspicious",
    reason: reasonText,
    recommended_action: verdict === "dangerous"
      ? "Leave the page and do not enter any information."
      : "Review the page carefully before clicking or sharing details.",
  };
}

export async function getGeminiExplanation({ url, score, signals, visibleText }) {
  if (score < 20) return null;
  if (OPENROUTER_API_KEY.includes("YOUR_FREE_KEY_HERE")) return null;

  const topSignals = signals
    .slice()
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((s) => `- ${s.reason}`)
    .join("\n");

  const textSnippet = visibleText.slice(0, 600);

  const prompt = `You are a cybersecurity assistant. Analyze this web page and explain the risk clearly to a non-technical user.

URL: ${url}
Risk Score: ${score}/100 (${score >= 70 ? "DANGEROUS" : "SUSPICIOUS"})

Top detected signals:
${topSignals}

Page text snippet:
"${textSnippet}"

Respond with a JSON object only, no markdown, in this exact shape:
{
  "verdict": "dangerous" | "suspicious" | "safe",
  "headline": "one sentence summary under 12 words",
  "reason": "2-3 sentence plain-English explanation of why this is risky",
  "recommended_action": "what the user should do right now"
}`;

  try {
    const response = await fetch(OPENROUTER_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
        "HTTP-Referer": "https://github.com/Henrycoding-design/Scam-detection-LotusHack2026",
      },
      body: JSON.stringify({
        model: "meta-llama/llama-3.1-8b-instruct:free",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.1,
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

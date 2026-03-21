// scoring/model.js — AI explanation via OpenRouter (free model)

const OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions";

async function loadApiKey() {
  try {
    const { OPENROUTER_API_KEY } = await import("./config.js");
    return OPENROUTER_API_KEY;
  } catch {
    return null;
  }
}

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

export async function getAiExplanation({ url, score, signals, visibleText }) {
  if (score < 20) return null;

  const apiKey = await loadApiKey();
  if (!apiKey) return null;

  const topSignals = signals
    .slice()
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((s) => `- ${s.reason}`)
    .join("\n");

  const textSnippet = visibleText.slice(0, 1000);

  const prompt = `You are a cybersecurity assistant explaining web page risks to a non-technical user. Be thorough and educational.

URL: ${url}
Risk Score: ${score}/100 (${score >= 70 ? "DANGEROUS" : "SUSPICIOUS"})

Detected warning signals:
${topSignals}

Page text snippet:
"${textSnippet}"

Respond with a JSON object only, no markdown. The "reason" field should be a DETAILED multi-sentence explanation (5-10 sentences) covering:
1. What specifically was detected and where on the page
2. Why each signal is dangerous in plain English
3. What a scammer could do if the user engages with this page
4. Real-world examples of similar scams if relevant
5. How to verify whether the page is legitimate or not

JSON shape:
{
  "verdict": "dangerous" | "suspicious" | "safe",
  "headline": "one sentence summary of the risk",
  "reason": "detailed multi-paragraph explanation as described above",
  "recommended_action": "specific immediate steps the user should take"
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

// scoring/gemini.js

// WARNING: Hardcoding API keys in a Chrome Extension is insecure for production.
// Anyone can inspect the extension files and steal the key.
// We are doing this TEMPORARILY for Step 2 testing. 
// In Step 3, this entire file will be moved to a secure backend server.
const GEMINI_API_KEY = "YOUR_GEMINI_API_KEY_HERE"; 
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`;

export async function getGeminiExplanation({ url, score, signals, visibleText }) {
  // Only call Gemini if score is suspicious or dangerous (saves quota)
  if (score < 30) return null;

  const topSignals = signals
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((s) => `- ${s.reason}`)
    .join("\n");

  const textSnippet = visibleText.slice(0, 600); // keep prompt lean

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
    const response = await fetch(GEMINI_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.1,       // low temp = consistent, factual output
          responseMimeType: "application/json",
        },
      }),
    });

    if (!response.ok) {
      console.warn("[ScamShield] Gemini API error:", response.status);
      return null;
    }

    const data = await response.json();
    const rawText = data.candidates?.[0]?.content?.parts?.[0]?.text || "";

    // Strip any accidental markdown fences
    const cleaned = rawText.replace(/```json|```/g, "").trim();
    return JSON.parse(cleaned);
  } catch (err) {
    console.warn("[ScamShield] Gemini parse error:", err);
    return null; // graceful fallback — scoring still works without it
  }
}

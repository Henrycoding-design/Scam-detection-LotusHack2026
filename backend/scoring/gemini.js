import { GoogleGenAI } from "@google/genai";

export async function getGeminiExplanation({ url, score, signals, visibleText }) {
  if (score < 30) return null;

  const topSignals = signals
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
    const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
    const response = await ai.models.generateContent({
      model: "gemini-3-flash-preview",
      contents: prompt,
      config: {
        temperature: 0.1,
        responseMimeType: "application/json",
      },
    });

    const rawText = response.text || "";
    const cleaned = rawText.replace(/```json|```/g, "").trim();
    return JSON.parse(cleaned);
  } catch (err) {
    console.warn("[ScamShield] Gemini parse error:", err);
    return null;
  }
}

import { scoreUrl } from "./heuristics.js";

export function runScoring({ url, links, text }) {
  const signals = [];
  let score = 0;

  // ── URL checks ────────────────────────────────────────────────────
  const urlSignals = scoreUrl(url);
  signals.push(...urlSignals);

  // ── Text checks ───────────────────────────────────────────────────
  const urgencyMatches = text.match(/urgent|verify|account suspended|confirm|unusual activity/gi) || [];
  if (urgencyMatches.length >= 2) {
    signals.push({ type: "urgency_language", weight: 25,
      reason: "Urgency/fear language detected" });
  } else if (urgencyMatches.length === 1) {
    signals.push({ type: "urgency_language_mild", weight: 10,
      reason: "Mild urgency language detected" });
  }

  const sensitiveMatches = text.match(/password|credit card|social security|bank account|wire transfer|gift card/gi) || [];
  if (sensitiveMatches.length > 0) {
    signals.push({ type: "sensitive_data_request", weight: 30,
      reason: "Page requests sensitive information" });
  }

  // ── Link density ──────────────────────────────────────────────────
  if (links.length > 30) {
    signals.push({ type: "high_link_density", weight: 15,
      reason: `Unusually high link count (${links.length})` });
  }

  // ── Login pattern on suspicious domain ───────────────────────────
  const hasLoginKeyword = /log.?in|sign.?in|password|verify/i.test(text);
  const urlHasLoginPath = /login|signin|verify|secure|auth/i.test(url);
  const isKnownDomain = /google|facebook|github|microsoft|apple/.test(new URL(url).hostname);
  if ((hasLoginKeyword || urlHasLoginPath) && !isKnownDomain) {
    signals.push({ type: "suspicious_login_pattern", weight: 30,
      reason: "Login pattern on unrecognized domain" });
  }

  // ── Weighted sum ──────────────────────────────────────────────────
  score = Math.min(100, signals.reduce((sum, s) => sum + s.weight, 0));

  const verdict = score >= 70 ? "dangerous" : score >= 30 ? "suspicious" : "safe";
  const reasons = signals
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 3)
    .map((s) => s.reason);

  return { score, verdict, reasons, signals };
}

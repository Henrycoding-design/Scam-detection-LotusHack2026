// scoring/analysis.js

export function getVerdict(score) {
  if (score >= 70) return "dangerous";
  if (score >= 30) return "suspicious";
  return "safe";
}

export function getTopSignals(signals, count = 3) {
  return [...signals]
    .sort((a, b) => b.weight - a.weight)
    .slice(0, count);
}

export function classifyScamType({ signals, subjectType = "page" }) {
  const types = new Set(signals.map((signal) => signal.type));

  if (types.has("crypto_scam_language")) {
    return "crypto giveaway scam";
  }

  if (types.has("sensitive_data_request")) {
    return "credential phishing";
  }

  if (
    types.has("brand_impersonation_page") ||
    types.has("brand_impersonation_link") ||
    types.has("offsite_login_link")
  ) {
    return subjectType === "link"
      ? "fake account verification link"
      : "fake account verification scam";
  }

  if (types.has("url_shortener") || types.has("high_external_link_ratio")) {
    return "suspicious redirect scam";
  }

  if (types.has("urgency_language") || types.has("urgency_language_mild")) {
    return "urgent phishing lure";
  }

  return "suspicious phishing attempt";
}

export function buildAnalysisPayload({
  subjectType,
  url,
  score,
  signals,
  aiStatus = "pending",
  explanation = null,
  destinationSummary = null,
}) {
  const topSignals = getTopSignals(signals);
  const fallback = buildFallbackDetails({
    subjectType,
    url,
    score,
    signals: topSignals,
    destinationSummary,
  });

  return {
    subjectType,
    url,
    score,
    verdict: explanation?.verdict || getVerdict(score),
    scamType: explanation?.scam_type || fallback.scamType,
    signals: topSignals,
    aiStatus,
    explanation,
    destinationSummary,
    headline: explanation?.headline || fallback.headline,
    reason: explanation?.reason || fallback.reason,
    riskLocation: explanation?.risk_location || fallback.riskLocation,
    preventionTips: explanation?.prevention_tips || fallback.preventionTips,
    recommendedAction:
      explanation?.recommended_action || fallback.recommendedAction,
  };
}

function buildFallbackDetails({ subjectType, url, signals, destinationSummary }) {
  const scamType = classifyScamType({ signals, subjectType });
  const indicatorText = signals.length
    ? signals
        .slice(0, 2)
        .map((signal) => signal.reason.toLowerCase())
        .join(" and ")
    : "the destination behaves like a common scam pattern";

  const subjectLabel = subjectType === "link" ? "link" : "page";
  const reason = `This ${subjectLabel} looks like a ${scamType} because ${indicatorText}.`;
  const riskLocation = inferRiskLocation({
    subjectType,
    signals,
    destinationSummary,
  });

  return {
    scamType,
    headline: scamTypeToHeadline(scamType),
    reason,
    riskLocation,
    recommendedAction:
      subjectType === "link"
        ? "Do not open the destination unless you verify it through an official source."
        : "Do not enter passwords, payment details, or codes until you verify the site.",
    preventionTips: buildPreventionTips(scamType, url),
  };
}

function inferRiskLocation({ subjectType, signals, destinationSummary }) {
  const signalTypes = new Set(signals.map((signal) => signal.type));

  if (
    signalTypes.has("sensitive_data_request") ||
    signalTypes.has("offsite_login_link")
  ) {
    return "The riskiest part is likely the sign-in or verification form asking for sensitive information.";
  }

  if (
    signalTypes.has("brand_impersonation_page") ||
    signalTypes.has("brand_impersonation_link")
  ) {
    return "The scam is likely in the domain and branding, which appear to imitate a trusted company.";
  }

  if (signalTypes.has("url_shortener") || signalTypes.has("high_external_link_ratio")) {
    return "The risk is likely in the destination URL or redirect path rather than the visible link label.";
  }

  if (destinationSummary?.snippet) {
    return "The suspicious behavior appears in the fetched destination content, which shows pressure or account-verification language.";
  }

  if (subjectType === "link") {
    return "The destination URL itself looks suspicious and should be treated as unsafe.";
  }

  return "The scam indicators are spread across the page content and domain signals.";
}

function buildPreventionTips(scamType, url) {
  const urlHost = safeHostname(url);

  if (scamType === "crypto giveaway scam") {
    return [
      "Never share wallet seed phrases or recovery phrases.",
      "Ignore giveaways that require urgent wallet connection.",
      "Verify promotions on the official project site, not social links.",
    ];
  }

  if (scamType.includes("verification") || scamType.includes("credential")) {
    return [
      "Type the official website address manually instead of trusting links.",
      `Check whether the domain exactly matches the real service before signing in${urlHost ? ` (${urlHost})` : ""}.`,
      "Be suspicious of pages demanding immediate login, code entry, or identity confirmation.",
    ];
  }

  return [
    "Pause before clicking unfamiliar links, especially on urgent messages.",
    "Verify the domain and page purpose before entering any personal details.",
    "When in doubt, leave the page and reach the service through an official channel.",
  ];
}

function scamTypeToHeadline(scamType) {
  const label = scamType.charAt(0).toUpperCase() + scamType.slice(1);
  return `Likely ${label}`;
}

function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

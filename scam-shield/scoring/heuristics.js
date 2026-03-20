// scoring/heuristics.js

export function scorePageContext(context) {
  const signals = [];
  let totalScore = 0;

  // ── SIGNAL 1: Suspicious domain patterns ──────────────────────────
  const url = new URL(context.url);
  const domainSignals = checkDomain(url);
  signals.push(...domainSignals);

  // ── SIGNAL 2: Page text keyword scan ──────────────────────────────
  const textSignals = checkText(context.visibleText, context.title);
  signals.push(...textSignals);

  // ── SIGNAL 3: Link analysis ────────────────────────────────────────
  const linkSignals = checkLinks(context.links, url.hostname);
  signals.push(...linkSignals);

  // ── SIGNAL 4: Meta tag checks ──────────────────────────────────────
  const metaSignals = checkMeta(context.meta);
  signals.push(...metaSignals);

  // Weighted sum, capped at 100
  totalScore = Math.min(
    100,
    signals.reduce((sum, s) => sum + s.weight, 0)
  );

  return { score: totalScore, signals };
}

// Per-link score (used to populate riskMap)
export function scoreSingleLink(href, pageHostname) {
  try {
    const url = new URL(href);
    const signals = checkDomain(url, pageHostname);
    const score = Math.min(100, signals.reduce((s, sig) => s + sig.weight, 0));
    return { score, signals };
  } catch {
    return { score: 0, signals: [] };
  }
}

// ── DOMAIN CHECKS ─────────────────────────────────────────────────────
function checkDomain(url, pageHostname = null) {
  const signals = [];
  const host = url.hostname.toLowerCase();

  // Homograph / typosquat patterns (e.g. paypa1.com, g00gle.com)
  if (/[0-9]/.test(host.replace(/\.[a-z]{2,}$/, ""))) {
    signals.push({ type: "digit_in_domain", weight: 20,
      reason: "Domain contains digits mimicking letters" });
  }

  // Excessive subdomains (e.g. secure.login.paypal.phish.com)
  const parts = host.split(".");
  if (parts.length > 4) {
    signals.push({ type: "excessive_subdomains", weight: 25,
      reason: `Unusual subdomain depth (${parts.length} levels)` });
  }

  // Suspicious TLDs
  const suspiciousTLDs = [".xyz", ".top", ".click", ".loan", ".work", ".gq", ".tk", ".ml"];
  if (suspiciousTLDs.some((tld) => host.endsWith(tld))) {
    signals.push({ type: "suspicious_tld", weight: 20,
      reason: `Suspicious TLD: ${url.hostname.split(".").pop()}` });
  }

  // Brand impersonation keywords in domain
  const brands = ["paypal", "amazon", "google", "apple", "microsoft",
                  "netflix", "bank", "secure", "verify", "login"];
  const matchedBrand = brands.find((b) => host.includes(b));
  if (matchedBrand && pageHostname && !host.includes(pageHostname.split(".")[0])) {
    signals.push({ type: "brand_impersonation", weight: 35,
      reason: `Domain impersonates "${matchedBrand}"` });
  }

  // IP address as hostname
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    signals.push({ type: "ip_address_host", weight: 40,
      reason: "Link goes directly to an IP address" });
  }

  // URL shorteners (obfuscation)
  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
                      "rb.gy", "cutt.ly", "short.io"];
  if (shorteners.some((s) => host.endsWith(s))) {
    signals.push({ type: "url_shortener", weight: 15,
      reason: "Link uses a URL shortener (destination hidden)" });
  }

  return signals;
}

// ── TEXT CHECKS ───────────────────────────────────────────────────────
function checkText(text, title) {
  const signals = [];
  const combined = `${title} ${text}`.toLowerCase();

  const urgencyPhrases = [
    "act now", "urgent", "immediate action", "account suspended",
    "verify your account", "confirm your identity", "unusual activity",
    "you have been selected", "claim your prize", "limited time",
    "your account will be closed", "security alert",
  ];
  const matched = urgencyPhrases.filter((p) => combined.includes(p));
  if (matched.length >= 2) {
    signals.push({ type: "urgency_language", weight: 25,
      reason: `Urgency/fear tactics detected: "${matched.slice(0, 2).join('", "')}"` });
  } else if (matched.length === 1) {
    signals.push({ type: "urgency_language_mild", weight: 10,
      reason: `Mild urgency language: "${matched[0]}"` });
  }

  // Login / payment form language on unexpected page
  const sensitivePatterns = [
    "enter your password", "social security", "credit card number",
    "bank account", "wire transfer", "bitcoin", "gift card",
  ];
  const sensitiveMatched = sensitivePatterns.filter((p) => combined.includes(p));
  if (sensitiveMatched.length > 0) {
    signals.push({ type: "sensitive_data_request", weight: 30,
      reason: `Requests sensitive info: "${sensitiveMatched[0]}"` });
  }

  return signals;
}

// ── LINK CHECKS ───────────────────────────────────────────────────────
function checkLinks(links, pageHostname) {
  const signals = [];

  // High ratio of external links (link farm / redirect page)
  const externalLinks = links.filter(
    (l) => !new URL(l.href).hostname.includes(pageHostname)
  );
  const externalRatio = links.length > 0 ? externalLinks.length / links.length : 0;
  if (links.length > 10 && externalRatio > 0.8) {
    signals.push({ type: "high_external_link_ratio", weight: 20,
      reason: `${Math.round(externalRatio * 100)}% of links go to external domains` });
  }

  // Links with login keywords pointing off-domain
  const loginLinks = links.filter(
    (l) => l.hasLoginKeyword && !new URL(l.href).hostname.includes(pageHostname)
  );
  if (loginLinks.length > 0) {
    signals.push({ type: "offsite_login_link", weight: 35,
      reason: `${loginLinks.length} login/verify link(s) pointing to external domains` });
  }

  return signals;
}

// ── META CHECKS ───────────────────────────────────────────────────────
function checkMeta(meta) {
  const signals = [];

  // No description meta = thin/fake page
  if (!meta["description"] && !meta["og:description"]) {
    signals.push({ type: "no_meta_description", weight: 8,
      reason: "Page has no description meta tag (thin content)" });
  }

  // Mismatched OG title vs actual domain
  const ogSiteName = (meta["og:site_name"] || "").toLowerCase();
  const ogUrl = meta["og:url"] || "";
  if (ogSiteName && ogUrl) {
    try {
      const ogHost = new URL(ogUrl).hostname.toLowerCase();
      if (!ogHost.includes(ogSiteName.replace(/\s+/g, ""))) {
        signals.push({ type: "og_domain_mismatch", weight: 15,
          reason: `OG site name "${ogSiteName}" doesn't match its URL` });
      }
    } catch { /* invalid URL in meta — itself slightly suspicious */ }
  }

  return signals;
}

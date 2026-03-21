// scoring/heuristics.js — Multi-layer scam detection engine
// Score: 100 = fully safe, 0 = extremely dangerous

import { detectHomograph } from "./homograph.js";
import { checkForms, checkIframes, checkScripts } from "./domAnalysis.js";
import { checkBlocklist } from "./blocklist.js";

// ── Category weights (must sum to 1.0) ────────────────────────────────
const CATEGORY_WEIGHTS = {
  domain: 0.30,   // Domain trust: TLD, brand, homograph, structure
  content: 0.20,  // Page content: urgency, crypto, sensitive data
  links: 0.15,    // Link safety: external ratio, login links
  forms: 0.15,    // Form safety: credential fields, cross-origin
  behavior: 0.10, // JS behavior: obfuscation, devtools blocking
  intel: 0.10,    // External intel: blocklist, domain age
};

// ── Main scoring function ─────────────────────────────────────────────
export function scorePageContext(context) {
  const url = new URL(context.url);
  const signals = [];

  // Layer 1: Domain checks
  const domainSignals = checkDomain(url);
  signals.push(...domainSignals);

  // Layer 2: Homograph detection
  const homographSignals = detectHomograph(context.url);
  signals.push(...homographSignals);

  // Layer 3: Content checks
  const contentSignals = checkText(context.visibleText, context.title);
  signals.push(...contentSignals);

  // Layer 4: Link checks
  const linkSignals = checkLinks(context.links, url.hostname);
  signals.push(...linkSignals);

  // Layer 5: Meta checks
  const metaSignals = checkMeta(context.meta);
  signals.push(...metaSignals);

  // Layer 6: DOM analysis (forms, iframes, scripts)
  if (context.formInfo) signals.push(...checkForms(context.formInfo, url.hostname));
  if (context.iframeInfo) signals.push(...checkIframes(context.iframeInfo));
  if (context.scriptInfo) signals.push(...checkScripts(context.scriptInfo));

  // Layer 7: Blocklist (synchronous, blocklistSet must be loaded)
  if (context.blocklistHit) {
    signals.push(context.blocklistHit);
  }

  // Layer 8: Domain age (may be null if not yet fetched)
  if (context.domainAgeSignal) {
    signals.push(context.domainAgeSignal);
  }

  // Calculate category-level risk scores (max risk per category)
  const categoryRisks = {};
  for (const [cat, signals_] of Object.entries(groupByCategory(signals))) {
    categoryRisks[cat] = Math.max(...signals_.map((s) => s.risk), 0);
  }

  // Weighted safety score: 100 = safe, 0 = dangerous
  let safetyScore = 100;
  for (const [cat, weight] of Object.entries(CATEGORY_WEIGHTS)) {
    const risk = categoryRisks[cat] || 0;
    safetyScore -= risk * weight;
  }
  safetyScore = Math.max(0, Math.round(safetyScore));

  // Confidence: how many categories contributed signals
  const categoriesWithSignals = Object.values(categoryRisks).filter((r) => r > 0).length;
  const totalCategories = Object.keys(CATEGORY_WEIGHTS).length;
  const confidence = categoriesWithSignals / totalCategories;

  return { score: safetyScore, signals, confidence };
}

export function buildTopReasons(signals, limit = 3) {
  return signals
    .slice()
    .sort((a, b) => b.risk - a.risk)
    .slice(0, limit)
    .map((s) => ({ reason: s.reason, detail: s.detail || "", risk: s.risk }));
}

export function scoreSingleLink(href, pageHostname) {
  try {
    const url = new URL(href);
    const signals = checkDomain(url, pageHostname);
    const homographSignals = detectHomograph(href);
    signals.push(...homographSignals);
    const maxRisk = Math.max(...signals.map((s) => s.risk), 0);
    const safetyScore = Math.max(0, 100 - maxRisk);
    return { score: safetyScore, signals };
  } catch {
    return { score: 100, signals: [] };
  }
}

// ── Helpers ────────────────────────────────────────────────────────────

function groupByCategory(signals) {
  const groups = {};
  const categoryMap = {
    digit_in_domain: "domain",
    excessive_subdomains: "domain",
    suspicious_tld: "domain",
    brand_impersonation_link: "domain",
    brand_impersonation_page: "domain",
    many_dashes: "domain",
    ip_address_host: "domain",
    url_shortener: "domain",
    mixed_script_hostname: "domain",
    homograph_brand_impersonation: "domain",
    non_ascii_hostname: "domain",
    urgency_language: "content",
    urgency_language_mild: "content",
    crypto_scam_language: "content",
    sensitive_data_request: "content",
    high_external_link_ratio: "links",
    offsite_login_link: "links",
    cross_origin_form: "forms",
    unexpected_password_form: "forms",
    excessive_hidden_inputs: "forms",
    hidden_iframe: "forms",
    cross_origin_iframe: "forms",
    jsfuck_obfuscation: "behavior",
    eval_atob_chain: "behavior",
    blocks_right_click: "behavior",
    blocks_devtools: "behavior",
    crypto_miner: "behavior",
    excessive_inline_scripts: "behavior",
    blocklist_hit: "intel",
    blocklist_parent_hit: "intel",
    domain_age_very_new: "intel",
    domain_age_new: "intel",
    domain_age_young: "intel",
    no_meta_description: "content",
    og_domain_mismatch: "content",
  };
  for (const signal of signals) {
    const cat = categoryMap[signal.type] || "content";
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(signal);
  }
  return groups;
}

// ── DOMAIN CHECKS ─────────────────────────────────────────────────────
function checkDomain(url, pageHostname = null) {
  const signals = [];
  const host = url.hostname.toLowerCase();

  // Digit substitution (paypa1.com)
  if (/[0-9]/.test(host.replace(/\.[a-z]{2,}$/, ""))) {
    signals.push({ type: "digit_in_domain", risk: 30,
      reason: "Domain contains digits mimicking letters",
      detail: "Scammers register domains like 'paypa1.com' or 'g00gle.com' — replacing letters with similar-looking numbers. This tricks people into thinking they're on a real website when they're actually on a fake one designed to steal your information." });
  }

  // Excessive subdomains
  const parts = host.split(".");
  if (parts.length > 4) {
    signals.push({ type: "excessive_subdomains", risk: 35,
      reason: `Unusual subdomain depth (${parts.length} levels)`,
      detail: `This URL has ${parts.length} levels of subdomains. Legitimate websites rarely use more than 2-3 levels. Scammers stack subdomains like 'secure.login.paypal.fake-site.com' to make the URL look official — but the real domain is the last two parts before the slash.` });
  }

  // Suspicious TLDs
  const suspiciousTLDs = [".xyz", ".top", ".click", ".loan", ".work", ".gq", ".tk", ".ml", ".cc", ".biz", ".info", ".buzz", ".surf", ".cam", ".monster"];
  if (suspiciousTLDs.some((tld) => host.endsWith(tld))) {
    const tld = url.hostname.split(".").pop();
    signals.push({ type: "suspicious_tld", risk: 30,
      reason: `Suspicious TLD: .${tld}`,
      detail: `The domain ends in '.${tld}', which is a top-level domain commonly abused by scammers because it's very cheap or free to register. While not every .${tld} site is malicious, legitimate businesses almost always use .com, .org, or country-specific domains.` });
  }

  // Brand impersonation
  const brands = ["paypal", "amazon", "google", "apple", "microsoft",
                  "netflix", "chase", "wellsfargo", "bank", "secure", "verify", "login", "support"];
  const matchedBrand = brands.find((b) => host.includes(b));

  if (matchedBrand && pageHostname && !host.includes(pageHostname.split(".")[0])) {
    signals.push({ type: "brand_impersonation_link", risk: 55,
      reason: `Link impersonates "${matchedBrand}"`,
      detail: `This link contains the word '${matchedBrand}' in its URL, but it doesn't actually belong to ${matchedBrand}. Scammers create fake URLs like '${matchedBrand}-secure-login.com' to trick you into entering your password on a phishing page.` });
  } else if (matchedBrand && !pageHostname && !host.endsWith(`${matchedBrand}.com`) && !host.endsWith(`${matchedBrand}.net`)) {
    signals.push({ type: "brand_impersonation_page", risk: 60,
      reason: `Domain impersonates "${matchedBrand}"`,
      detail: `This website's domain contains '${matchedBrand}' but isn't the official ${matchedBrand}.com site. Scammers register lookalike domains to steal login credentials and personal information.` });
  }

  // Many dashes
  if (host.split("-").length > 3) {
    signals.push({ type: "many_dashes", risk: 25,
      reason: "Domain contains many dashes (common in phishing)",
      detail: "This domain has multiple dashes, like 'secure-update-account-info.com'. Scammers use long hyphenated domains to cram in keywords that make the URL look official." });
  }

  // IP address as hostname
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    signals.push({ type: "ip_address_host", risk: 60,
      reason: "Link goes directly to an IP address",
      detail: "Instead of a normal domain name, this link uses a raw IP address. Legitimate websites almost never use IP addresses directly. This is a common technique used by scammers hosting temporary phishing pages on compromised servers." });
  }

  // URL shorteners
  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
                      "rb.gy", "cutt.ly", "short.io", "is.gd", "v.gd", "buff.ly"];
  if (shorteners.some((s) => host.endsWith(s))) {
    signals.push({ type: "url_shortener", risk: 20,
      reason: "Link uses a URL shortener (destination hidden)",
      detail: "This link uses a URL shortening service, which hides the real destination. Scammers abuse URL shorteners to mask dangerous links." });
  }

  return signals;
}

// ── TEXT CHECKS ───────────────────────────────────────────────────────
function checkText(text, title) {
  const signals = [];
  const combined = `${title} ${text}`.toLowerCase();

  const urgencyRegex = /urgent|immediate action|account suspended|verify your account|confirm your identity|unusual activity|claim your prize|limited time|security alert|account locked|action required/gi;
  const urgencyMatches = combined.match(urgencyRegex) || [];
  const uniqueUrgency = new Set(urgencyMatches.map(m => m.toLowerCase()));

  if (uniqueUrgency.size >= 2) {
    const phrases = [...uniqueUrgency].map(p => `"${p}"`).join(", ");
    signals.push({ type: "urgency_language", risk: 40,
      reason: "Multiple urgency/fear tactics detected",
      detail: `This page uses pressure phrases like ${phrases}. Scammers create a false sense of urgency to make you panic and act without thinking.` });
  } else if (uniqueUrgency.size === 1) {
    signals.push({ type: "urgency_language_mild", risk: 20,
      reason: "Mild urgency language detected",
      detail: "This page uses urgency language to pressure you into acting quickly. Scammers frequently use time pressure to prevent you from thinking critically." });
  }

  const cryptoRegex = /seed phrase|recovery phrase|wallet connect|airdrop|double your crypto|giveaway/i;
  if (cryptoRegex.test(combined)) {
    signals.push({ type: "crypto_scam_language", risk: 50,
      reason: "High-risk crypto/giveaway keywords detected",
      detail: "This page mentions cryptocurrency giveaways, seed phrases, or doubling your crypto. No legitimate service will ever ask for your seed/recovery phrase, and no one gives away free cryptocurrency." });
  }

  const sensitiveRegex = /social security|credit card number|routing number|wire transfer|enter your password/i;
  if (sensitiveRegex.test(combined)) {
    signals.push({ type: "sensitive_data_request", risk: 45,
      reason: "Requests highly sensitive personal info",
      detail: "This page asks for extremely sensitive information like Social Security numbers, credit card details, or passwords. If you didn't initiate this request through a verified official channel, do not enter any personal data." });
  }

  return signals;
}

// ── LINK CHECKS ───────────────────────────────────────────────────────
function checkLinks(links, pageHostname) {
  const signals = [];

  const externalLinks = links.filter(
    (l) => !new URL(l.href).hostname.includes(pageHostname)
  );
  const externalRatio = links.length > 0 ? externalLinks.length / links.length : 0;

  if (links.length >= 3 && externalRatio > 0.7) {
    signals.push({ type: "high_external_link_ratio", risk: 35,
      reason: `${Math.round(externalRatio * 100)}% of links go to external domains`,
      detail: `Almost all the links on this page lead to other websites instead of staying on the same domain. This suggests this page exists primarily to redirect you elsewhere.` });
  }

  const loginLinks = links.filter(
    (l) => l.hasLoginKeyword && !new URL(l.href).hostname.includes(pageHostname)
  );
  if (loginLinks.length > 0) {
    signals.push({ type: "offsite_login_link", risk: 50,
      reason: `${loginLinks.length} login/verify link(s) pointing to external domains`,
      detail: "This page contains links with words like 'login' or 'verify' that send you to a different website. This is a classic phishing technique." });
  }

  return signals;
}

// ── META CHECKS ───────────────────────────────────────────────────────
function checkMeta(meta) {
  const signals = [];

  if (!meta["description"] && !meta["og:description"]) {
    signals.push({ type: "no_meta_description", risk: 10,
      reason: "Page has no description meta tag (thin content)",
      detail: "This page has no description metadata. While not dangerous by itself, this often indicates a hastily-created page." });
  }

  const ogSiteName = (meta["og:site_name"] || "").toLowerCase();
  const ogUrl = meta["og:url"] || "";
  if (ogSiteName && ogUrl) {
    try {
      const ogHost = new URL(ogUrl).hostname.toLowerCase();
      if (!ogHost.includes(ogSiteName.replace(/\s+/g, ""))) {
        signals.push({ type: "og_domain_mismatch", risk: 25,
          reason: `OG site name "${ogSiteName}" doesn't match its URL`,
          detail: `This page claims to be "${ogSiteName}" in its metadata, but its URL points to a different website.` });
      }
    } catch { /* invalid URL */ }
  }

  return signals;
}

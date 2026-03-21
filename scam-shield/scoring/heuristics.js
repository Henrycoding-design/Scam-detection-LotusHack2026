// scoring/heuristics.js

export function scorePageContext(context) {
  const signals = [];
  let totalScore = 0;

  const url = new URL(context.url);
  const domainSignals = checkDomain(url);
  signals.push(...domainSignals);

  const textSignals = checkText(context.visibleText, context.title);
  signals.push(...textSignals);

  const linkSignals = checkLinks(context.links, url.hostname);
  signals.push(...linkSignals);

  const metaSignals = checkMeta(context.meta);
  signals.push(...metaSignals);

  totalScore = Math.min(
    100,
    signals.reduce((sum, s) => sum + s.weight, 0)
  );

  return { score: totalScore, signals };
}

export function buildTopReasons(signals, limit = 3) {
  return signals
    .slice()
    .sort((a, b) => b.weight - a.weight)
    .slice(0, limit)
    .map((s) => ({ reason: s.reason, detail: s.detail || "" }));
}

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

  if (/[0-9]/.test(host.replace(/\.[a-z]{2,}$/, ""))) {
    signals.push({ type: "digit_in_domain", weight: 20,
      reason: "Domain contains digits mimicking letters",
      detail: "Scammers often register domains like 'paypa1.com' or 'g00gle.com' — replacing letters with similar-looking numbers. This tricks people into thinking they're on a real website when they're actually on a fake one designed to steal your information." });
  }

  const parts = host.split(".");
  if (parts.length > 4) {
    signals.push({ type: "excessive_subdomains", weight: 25,
      reason: `Unusual subdomain depth (${parts.length} levels)`,
      detail: `This URL has ${parts.length} levels of subdomains (e.g. a.b.c.d.com). Legitimate websites rarely use more than 2-3 levels. Scammers stack subdomains like 'secure.login.paypal.fake-site.com' to make the URL look official — but the real domain is the last two parts before the slash.` });
  }

  const suspiciousTLDs = [".xyz", ".top", ".click", ".loan", ".work", ".gq", ".tk", ".ml", ".cc", ".biz"];
  if (suspiciousTLDs.some((tld) => host.endsWith(tld))) {
    const tld = url.hostname.split(".").pop();
    signals.push({ type: "suspicious_tld", weight: 20,
      reason: `Suspicious TLD: .${tld}`,
      detail: `The domain ends in '.${tld}', which is a top-level domain commonly abused by scammers because it's very cheap or free to register. While not every .${tld} site is malicious, legitimate businesses almost always use .com, .org, or country-specific domains.` });
  }

  const brands = ["paypal", "amazon", "google", "apple", "microsoft",
                  "netflix", "chase", "wellsfargo", "bank", "secure", "verify", "login", "support"];
  const matchedBrand = brands.find((b) => host.includes(b));

  if (matchedBrand && pageHostname && !host.includes(pageHostname.split(".")[0])) {
    signals.push({ type: "brand_impersonation_link", weight: 35,
      reason: `Link impersonates "${matchedBrand}"`,
      detail: `This link contains the word '${matchedBrand}' in its URL, but it doesn't actually belong to ${matchedBrand}. Scammers create fake URLs like '${matchedBrand}-secure-login.com' to trick you into entering your password on a phishing page. Always check that you're on the official website before logging in.` });
  } else if (matchedBrand && !pageHostname && !host.endsWith(`${matchedBrand}.com`) && !host.endsWith(`${matchedBrand}.net`)) {
    signals.push({ type: "brand_impersonation_page", weight: 40,
      reason: `Domain impersonates "${matchedBrand}"`,
      detail: `This website's domain contains '${matchedBrand}' but isn't the official ${matchedBrand}.com site. Scammers register lookalike domains to steal login credentials and personal information. The real ${matchedBrand} website would use '${matchedBrand}.com' — anything else should be treated with extreme caution.` });
  }

  if (host.split("-").length > 3) {
    signals.push({ type: "many_dashes", weight: 15,
      reason: "Domain contains many dashes (common in phishing)",
      detail: "This domain has multiple dashes, like 'secure-update-account-info.com'. Scammers use long hyphenated domains to cram in keywords that make the URL look official. Real companies almost never use this many dashes in their domain name." });
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    signals.push({ type: "ip_address_host", weight: 40,
      reason: "Link goes directly to an IP address",
      detail: "Instead of a normal domain name (like google.com), this link uses a raw IP address like '192.168.1.1'. Legitimate websites almost never use IP addresses directly. This is a common technique used by scammers hosting temporary phishing pages on compromised servers." });
  }

  const shorteners = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
                      "rb.gy", "cutt.ly", "short.io"];
  if (shorteners.some((s) => host.endsWith(s))) {
    signals.push({ type: "url_shortener", weight: 15,
      reason: "Link uses a URL shortener (destination hidden)",
      detail: "This link uses a URL shortening service, which hides the real destination. Scammers abuse URL shorteners to mask dangerous links — you click thinking it's one website, but you're actually sent somewhere completely different. Hover over shortened links to preview the real URL before clicking." });
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
    signals.push({ type: "urgency_language", weight: 30,
      reason: "Multiple urgency/fear tactics detected",
      detail: `This page uses pressure phrases like ${phrases}. Scammers create a false sense of urgency to make you panic and act without thinking. Real companies give you time to verify issues through their official apps or websites — they don't threaten you with countdown timers or immediate consequences.` });
  } else if (uniqueUrgency.size === 1) {
    signals.push({ type: "urgency_language_mild", weight: 15,
      reason: "Mild urgency language detected",
      detail: "This page uses urgency language to pressure you into acting quickly. While not always malicious, be cautious — scammers frequently use time pressure to prevent you from thinking critically about what you're being asked to do." });
  }

  const cryptoRegex = /seed phrase|recovery phrase|wallet connect|airdrop|double your crypto|giveaway/i;
  if (cryptoRegex.test(combined)) {
    signals.push({ type: "crypto_scam_language", weight: 35,
      reason: "High-risk crypto/giveaway keywords detected",
      detail: "This page mentions cryptocurrency giveaways, seed phrases, or doubling your crypto. These are hallmarks of scams — no legitimate service will ever ask for your seed/recovery phrase, and no one is giving away free cryptocurrency. 'Send 1 ETH to get 2 back' is always a scam." });
  }

  const sensitiveRegex = /social security|credit card number|routing number|wire transfer|enter your password/i;
  if (sensitiveRegex.test(combined)) {
    signals.push({ type: "sensitive_data_request", weight: 30,
      reason: "Requests highly sensitive personal info",
      detail: "This page asks for extremely sensitive information like Social Security numbers, credit card details, or passwords. Legitimate websites rarely ask for this information on a regular web page. If you didn't initiate this request through a verified official channel, do not enter any personal data." });
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
    signals.push({ type: "high_external_link_ratio", weight: 25,
      reason: `${Math.round(externalRatio * 100)}% of links go to external domains`,
      detail: `Almost all the links on this page lead to other websites instead of staying on the same domain. This is unusual for a legitimate site — it suggests this page exists primarily to redirect you elsewhere. Scammers create these 'link farm' pages to send traffic to phishing sites or malware downloads.` });
  }

  const loginLinks = links.filter(
    (l) => l.hasLoginKeyword && !new URL(l.href).hostname.includes(pageHostname)
  );
  if (loginLinks.length > 0) {
    signals.push({ type: "offsite_login_link", weight: 35,
      reason: `${loginLinks.length} login/verify link(s) pointing to external domains`,
      detail: "This page contains links with words like 'login', 'sign in', or 'verify' that send you to a different website. This is a classic phishing technique — you think you're clicking a login button for the site you're on, but you're actually being sent to a fake login page that steals your credentials." });
  }

  return signals;
}

// ── META CHECKS ───────────────────────────────────────────────────────
function checkMeta(meta) {
  const signals = [];

  if (!meta["description"] && !meta["og:description"]) {
    signals.push({ type: "no_meta_description", weight: 8,
      reason: "Page has no description meta tag (thin content)",
      detail: "This page has no description metadata — something almost every legitimate website includes for search engines and previews. While not dangerous by itself, this often indicates a hastily-created page. Scammers throw up phishing pages quickly and skip the metadata that real websites take time to set up." });
  }

  const ogSiteName = (meta["og:site_name"] || "").toLowerCase();
  const ogUrl = meta["og:url"] || "";
  if (ogSiteName && ogUrl) {
    try {
      const ogHost = new URL(ogUrl).hostname.toLowerCase();
      if (!ogHost.includes(ogSiteName.replace(/\s+/g, ""))) {
        signals.push({ type: "og_domain_mismatch", weight: 15,
          reason: `OG site name "${ogSiteName}" doesn't match its URL`,
          detail: `This page claims to be "${ogSiteName}" in its metadata, but its URL points to a completely different website. Scammers copy metadata from legitimate sites to make their phishing pages look genuine when shared on social media or in messaging apps.` });
      }
    } catch { /* invalid URL in meta */ }
  }

  return signals;
}

export function scoreUrl(urlString) {
  try {
    const url = new URL(urlString);
    return checkDomain(url);
  } catch {
    return [{ type: "invalid_url", weight: 20, reason: "Malformed URL" }];
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
  const suspiciousTLDs = [".xyz", ".top", ".click", ".loan", ".work", ".gq", ".tk", ".ml", ".cc", ".biz"];
  if (suspiciousTLDs.some((tld) => host.endsWith(tld))) {
    signals.push({ type: "suspicious_tld", weight: 20,
      reason: `Suspicious TLD: ${url.hostname.split(".").pop()}` });
  }

  // Brand impersonation keywords in domain
  const brands = ["paypal", "amazon", "google", "apple", "microsoft",
                  "netflix", "chase", "wellsfargo", "bank", "secure", "verify", "login", "support"];
  const matchedBrand = brands.find((b) => host.includes(b));
  
  // If it's a link check (pageHostname exists) and points off-site
  if (matchedBrand && pageHostname && !host.includes(pageHostname.split(".")[0])) {
    signals.push({ type: "brand_impersonation_link", weight: 35,
      reason: `Link impersonates "${matchedBrand}"` });
  } 
  // If it's a page check, flag if domain contains brand but isn't the official .com/.net
  else if (matchedBrand && !pageHostname && !host.endsWith(`${matchedBrand}.com`) && !host.endsWith(`${matchedBrand}.net`)) {
    signals.push({ type: "brand_impersonation_page", weight: 40,
      reason: `Domain impersonates "${matchedBrand}"` });
  }

  // Many dashes in domain (common in phishing e.g. secure-update-account-info.com)
  if (host.split("-").length > 3) {
    signals.push({ type: "many_dashes", weight: 15,
      reason: "Domain contains many dashes (common in phishing)" });
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

// scoring/domainAge.js — Domain age check via Certificate Transparency (crt.sh)

const CRT_SH_CACHE_PREFIX = "crtsh_";
const MAX_CACHE_AGE = 30 * 24 * 60 * 60 * 1000; // 30 days

export async function checkDomainAge(hostname) {
  // Check cache first
  const cached = await getCached(hostname);
  if (cached) return cached;

  // Query crt.sh (background, non-blocking)
  try {
    const response = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(hostname)}&output=json`,
      { signal: AbortSignal.timeout(5000) }
    );

    if (!response.ok) return null;

    const certs = await response.json();
    if (!Array.isArray(certs) || certs.length === 0) return null;

    // Find earliest certificate date
    let earliest = null;
    for (const cert of certs) {
      const date = new Date(cert.not_before || cert.entry_timestamp);
      if (!isNaN(date.getTime())) {
        if (!earliest || date < earliest) earliest = date;
      }
    }

    if (!earliest) return null;

    const ageMs = Date.now() - earliest.getTime();
    const ageDays = Math.floor(ageMs / (24 * 60 * 60 * 1000));
    const result = { firstCertDate: earliest.toISOString(), ageDays, signal: null };

    if (ageDays < 7) {
      result.signal = {
        type: "domain_age_very_new",
        risk: 55,
        reason: `Domain's first SSL certificate is only ${ageDays} day(s) old`,
        detail: `This domain received its first SSL certificate just ${ageDays} day(s) ago (${earliest.toLocaleDateString()}). Phishing pages are typically hosted on newly created domains that scammers register, use for a few days, and then abandon. While some legitimate new websites also have new certificates, the combination of a new domain with any other warning signal is extremely suspicious.`,
      };
    } else if (ageDays < 30) {
      result.signal = {
        type: "domain_age_new",
        risk: 35,
        reason: `Domain's first SSL certificate is ${ageDays} days old`,
        detail: `This domain's oldest SSL certificate dates to ${earliest.toLocaleDateString()} — only ${ageDays} days ago. Scammers frequently register fresh domains for phishing campaigns. While this alone doesn't prove malicious intent, it's a notable risk factor, especially when combined with other suspicious indicators.`,
      };
    } else if (ageDays < 90) {
      result.signal = {
        type: "domain_age_young",
        risk: 15,
        reason: `Domain is relatively young (${ageDays} days)`,
        detail: `This domain's first known SSL certificate is from ${earliest.toLocaleDateString()} — about ${ageDays} days old. Most established websites have certificates that are years old. A young domain isn't inherently dangerous, but it's worth noting in context with other signals.`,
      };
    }

    // Cache the result
    await setCached(hostname, result);
    return result;
  } catch {
    return null;
  }
}

async function getCached(hostname) {
  try {
    const key = `${CRT_SH_CACHE_PREFIX}${hostname}`;
    const { [key]: cached } = await chrome.storage.local.get(key);
    if (!cached) return null;
    if (Date.now() - cached.timestamp > MAX_CACHE_AGE) return null;
    return cached;
  } catch {
    return null;
  }
}

async function setCached(hostname, result) {
  try {
    const key = `${CRT_SH_CACHE_PREFIX}${hostname}`;
    await chrome.storage.local.set({
      [key]: { ...result, timestamp: Date.now() },
    });
  } catch {
    // Storage unavailable
  }
}

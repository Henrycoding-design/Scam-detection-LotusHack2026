// scoring/blocklist.js — Local phishing domain blocklist using Phishing.Database

const BLOCKLIST_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/ALL-phishing-domains.lst";
const CACHE_KEY = "phishing_blocklist";
const TIMESTAMP_KEY = "phishing_blocklist_ts";
const UPDATE_INTERVAL = 7 * 24 * 60 * 60 * 1000; // 1 week

let blocklistSet = null;

export async function initBlocklist() {
  if (blocklistSet) return;

  try {
    const { [CACHE_KEY]: cached } = await chrome.storage.local.get(CACHE_KEY);
    if (cached && cached.length > 0) {
      blocklistSet = new Set(cached);
    }
  } catch {
    // Storage unavailable
  }

  // Background update if stale
  const { [TIMESTAMP_KEY]: ts } = await chrome.storage.local.get(TIMESTAMP_KEY);
  if (!ts || Date.now() - ts > UPDATE_INTERVAL) {
    updateBlocklist().catch(() => {});
  }
}

async function updateBlocklist() {
  try {
    const response = await fetch(BLOCKLIST_URL);
    if (!response.ok) return;

    const text = await response.text();
    const domains = text
      .split("\n")
      .map((line) => line.trim().toLowerCase())
      .filter((line) => line && !line.startsWith("#"));

    if (domains.length > 0) {
      blocklistSet = new Set(domains);
      await chrome.storage.local.set({
        [CACHE_KEY]: domains,
        [TIMESTAMP_KEY]: Date.now(),
      });
    }
  } catch {
    // Network error — use cached version
  }
}

export function checkBlocklist(hostname) {
  if (!blocklistSet) return null;

  const host = hostname.toLowerCase();
  if (blocklistSet.has(host)) {
    return {
      type: "blocklist_hit",
      risk: 95,
      reason: "Domain is listed in known phishing database",
      detail: `The domain "${host}" appears in the Phishing.Database — a community-maintained list of over 496,000 known phishing domains. This domain has been confirmed as malicious by security researchers. Do not enter any information on this page and close it immediately.`,
    };
  }

  // Also check parent domain (e.g., "sub.phishing.com" → check "phishing.com")
  const parts = host.split(".");
  if (parts.length > 2) {
    const parent = parts.slice(-2).join(".");
    if (blocklistSet.has(parent)) {
      return {
        type: "blocklist_parent_hit",
        risk: 85,
        reason: "Parent domain is listed in known phishing database",
        detail: `The parent domain "${parent}" of "${host}" appears in the Phishing.Database. This means you're on a subdomain of a known phishing operation. Subdomains are commonly used to evade blocklists — the scammer registers a clean parent domain and hosts different phishing pages on different subdomains.`,
      };
    }
  }

  return null;
}

export function getBlocklistStats() {
  return {
    loaded: blocklistSet !== null,
    size: blocklistSet ? blocklistSet.size : 0,
  };
}

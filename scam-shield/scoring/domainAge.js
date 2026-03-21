// scoring/domainAge.js — Domain age via RDAP (free, no key needed)

const CACHE_PREFIX = "rdap_";
const MAX_AGE = 30 * 864e5; // 30 days

export async function checkDomainAge(hostname) {
  const cached = await get(hostname);
  if (cached) return cached;

  try {
    const res = await fetch(`https://rdap.org/domain/${hostname}`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;

    const data = await res.json();
    const events = data.events || [];
    const regEvent = events.find(e => e.eventAction === "registration" || e.eventAction === "create");
    if (!regEvent?.eventDate) return null;

    const regDate = new Date(regEvent.eventDate);
    const ageDays = Math.floor((Date.now() - regDate) / 864e5);
    let signal = null;

    if (ageDays < 7) signal = { type: "domain_age_new", category: "intel", risk: 55,
      reason: `Domain registered ${ageDays} day(s) ago`, detail: `Registered ${regDate.toLocaleDateString()}. Phishing domains are often freshly registered and abandoned within days.` };
    else if (ageDays < 30) signal = { type: "domain_age_young", category: "intel", risk: 35,
      reason: `Domain is ${ageDays} days old`, detail: `Registered ${regDate.toLocaleDateString()}. Fresh domains combined with other signals are highly suspicious.` };
    else if (ageDays < 90) signal = { type: "domain_age_moderate", category: "intel", risk: 15,
      reason: `Domain is ${ageDays} days old`, detail: `Registered ${regDate.toLocaleDateString()}. Worth noting alongside other signals.` };

    const result = { ageDays, signal };
    await set(hostname, result);
    return result;
  } catch { return null; }
}

async function get(host) {
  try {
    const { [CACHE_PREFIX + host]: v } = await chrome.storage.local.get(CACHE_PREFIX + host);
    return v && Date.now() - v.ts < MAX_AGE ? v : null;
  } catch { return null; }
}

async function set(host, val) {
  try { await chrome.storage.local.set({ [CACHE_PREFIX + host]: { ...val, ts: Date.now() } }); } catch {}
}

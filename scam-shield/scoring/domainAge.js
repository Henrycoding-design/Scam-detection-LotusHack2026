// scoring/domainAge.js — Domain age via RDAP (free, no key needed)

const CACHE_PREFIX = "rdap_";
const MAX_AGE = 30 * 864e5; // 30 days

function logStage(stage, payload = {}) {
  console.log(`[ScamShield][DomainAge] ${stage}`, payload);
}

export async function checkDomainAge(hostname) {
  const cached = await get(hostname);
  if (cached) {
    logStage("cache.hit", {
      hostname,
      ageDays: cached.ageDays ?? null,
      hasSignal: Boolean(cached.signal),
    });
    return cached;
  }

  try {
    logStage("fetch.start", { hostname });
    const res = await fetch(`https://rdap.org/domain/${hostname}`, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) {
      logStage("fetch.http_error", { hostname, status: res.status });
      return null;
    }

    const data = await res.json();
    const events = data.events || [];
    const regEvent = events.find(e => e.eventAction === "registration" || e.eventAction === "create");
    if (!regEvent?.eventDate) {
      logStage("fetch.no_registration_event", { hostname });
      return null;
    }

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
    logStage("fetch.complete", {
      hostname,
      ageDays,
      signalType: signal?.type || null,
    });
    return result;
  } catch (error) {
    logStage("fetch.error", {
      hostname,
      error: error?.message || String(error),
    });
    return null;
  }
}

async function get(host) {
  try {
    const { [CACHE_PREFIX + host]: v } = await chrome.storage.local.get(CACHE_PREFIX + host);
    const fresh = v && Date.now() - v.ts < MAX_AGE ? v : null;
    if (!fresh) {
      logStage("cache.miss", { hostname: host });
    }
    return fresh;
  } catch { return null; }
}

async function set(host, val) {
  try {
    await chrome.storage.local.set({ [CACHE_PREFIX + host]: { ...val, ts: Date.now() } });
    logStage("cache.write", { hostname: host, ageDays: val.ageDays ?? null });
  } catch {}
}

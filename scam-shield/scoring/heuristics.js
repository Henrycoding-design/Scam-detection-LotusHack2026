// scoring/heuristics.js — Multi-layer scam detection (100=safe, 0=dangerous)

import { detectHomograph } from "./homograph.js";

const WEIGHTS = { domain: .30, content: .20, links: .15, forms: .15, behavior: .10, intel: .10 };
const KNOWN_LOGIN = new Set([
  "google.com","facebook.com","apple.com","microsoft.com","amazon.com",
  "paypal.com","netflix.com","twitter.com","x.com","linkedin.com",
  "github.com","dropbox.com","chase.com","wellsfargo.com","bankofamerica.com",
  "instagram.com","discord.com","reddit.com","yahoo.com","ebay.com","spotify.com",
]);
const KNOWN_EMBEDS = ["youtube.com","vimeo.com","maps.google.com","spotify.com"];

// ── Main scorer ───────────────────────────────────────────────────────
export function scorePageContext(ctx) {
  const url = new URL(ctx.url);
  const signals = [
    ...checkDomain(url),
    ...detectHomograph(ctx.url),
    ...checkText(ctx.visibleText, ctx.title),
    ...checkLinks(ctx.links, url.hostname),
    ...checkMeta(ctx.meta),
    ...checkForms(ctx.formInfo, url.hostname),
    ...checkIframes(ctx.iframeInfo),
    ...checkScripts(ctx.scriptInfo),
  ];
  if (ctx.blocklistHit) signals.push(ctx.blocklistHit);
  if (ctx.domainAgeSignal) signals.push(ctx.domainAgeSignal);

  // Category-weighted: max risk per category → weighted safety
  const cats = {};
  for (const s of signals) cats[s.category] = Math.max(cats[s.category] || 0, s.risk);
  let score = 100;
  for (const [c, w] of Object.entries(WEIGHTS)) score -= (cats[c] || 0) * w;
  score = Math.max(0, Math.round(score));

  const confidence = Object.values(cats).filter(r => r > 0).length / Object.keys(WEIGHTS).length;
  return { score, signals, confidence };
}

export function buildTopReasons(signals, n = 3) {
  return signals.sort((a, b) => b.risk - a.risk).slice(0, n)
    .map(s => ({ reason: s.reason, detail: s.detail || "", risk: s.risk }));
}

export function scoreSingleLink(href, host) {
  try {
    const signals = [...checkDomain(new URL(href), host), ...detectHomograph(href)];
    return { score: Math.max(0, 100 - Math.max(...signals.map(s => s.risk), 0)), signals };
  } catch { return { score: 100, signals: [] }; }
}

// ── Domain ────────────────────────────────────────────────────────────
function checkDomain(url, pageHost) {
  const h = url.hostname.toLowerCase(), parts = h.split("."), sigs = [];
  const r = (type, risk, reason, detail) => sigs.push({ type, category: "domain", risk, reason, detail });

  if (/[0-9]/.test(h.replace(/\.[a-z]{2,}$/, "")))
    r("digit_in_domain", 30, "Domain contains digits mimicking letters",
      "Scammers register domains like 'paypa1.com' — replacing letters with similar-looking numbers.");

  if (parts.length > 4)
    r("excessive_subdomains", 35, `Unusual subdomain depth (${parts.length} levels)`,
      "Legitimate sites rarely use more than 2-3 subdomain levels. Scammers stack them to look official.");

  const tlds = [".xyz",".top",".click",".loan",".tk",".ml",".cc",".biz",".buzz",".surf",".cam",".monster"];
  if (tlds.some(t => h.endsWith(t)))
    r("suspicious_tld", 30, `Suspicious TLD: .${h.split(".").pop()}`,
      "Cheap/free TLDs are commonly abused by scammers.");

  const brands = ["paypal","amazon","google","apple","microsoft","netflix","chase","bank","secure","verify","login"];
  const brand = brands.find(b => h.includes(b));
  if (brand && pageHost && !h.includes(pageHost.split(".")[0]))
    r("brand_impersonation_link", 55, `Link impersonates "${brand}"`,
      `This link contains '${brand}' but doesn't belong to ${brand}.`);
  else if (brand && !pageHost && !h.endsWith(`${brand}.com`) && !h.endsWith(`${brand}.net`))
    r("brand_impersonation_page", 60, `Domain impersonates "${brand}"`,
      `This domain contains '${brand}' but isn't the official site.`);

  if (h.split("-").length > 3) r("many_dashes", 25, "Domain has many dashes", "Long hyphenated domains are a phishing pattern.");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) r("ip_address_host", 60, "Link uses raw IP address", "Legitimate sites almost never use IP addresses directly.");
  if (["bit.ly","tinyurl.com","t.co","ow.ly","rb.gy","cutt.ly","is.gd"].some(s => h.endsWith(s)))
    r("url_shortener", 20, "URL shortener hides destination", "Scammers mask dangerous links behind shorteners.");

  return sigs;
}

// ── Text ──────────────────────────────────────────────────────────────
function checkText(text, title) {
  const t = `${title} ${text}`.toLowerCase(), sigs = [];
  const r = (type, risk, reason, detail) => sigs.push({ type, category: "content", risk, reason, detail });

  const urgency = [...new Set((t.match(/urgent|immediate action|account suspended|verify your account|security alert|action required|claim your prize/gi) || []).map(m => m.toLowerCase()))];
  if (urgency.length >= 2)
    r("urgency_language", 40, "Multiple urgency/fear tactics detected", `Phrases like "${urgency.join('", "')}" pressure you to act without thinking.`);
  else if (urgency.length === 1)
    r("urgency_language_mild", 20, "Urgency language detected", "Scammers use time pressure to prevent critical thinking.");

  if (/seed phrase|recovery phrase|wallet connect|airdrop|double your crypto|giveaway/i.test(t))
    r("crypto_scam", 50, "Crypto/giveaway scam keywords detected", "No legitimate service asks for your seed phrase or gives away free crypto.");

  if (/social security|credit card number|routing number|wire transfer|enter your password/i.test(t))
    r("sensitive_data_request", 45, "Requests highly sensitive personal info", "Do not enter personal data unless you initiated this through a verified channel.");

  return sigs;
}

// ── Links ─────────────────────────────────────────────────────────────
function checkLinks(links, host) {
  const sigs = [];
  const r = (type, risk, reason, detail) => sigs.push({ type, category: "links", risk, reason, detail });

  const ext = links.filter(l => { try { return !new URL(l.href).hostname.includes(host); } catch { return false; } });
  if (links.length >= 3 && ext.length / links.length > 0.7)
    r("high_external_ratio", 35, `${Math.round(ext.length/links.length*100)}% of links go to external domains`,
      "This page primarily redirects elsewhere — a common link farm pattern.");

  const loginLinks = links.filter(l => l.hasLoginKeyword && (() => { try { return !new URL(l.href).hostname.includes(host); } catch { return false; } })());
  if (loginLinks.length)
    r("offsite_login_link", 50, `${loginLinks.length} login link(s) pointing elsewhere`,
      "Login/verify links on this page send you to a different domain — a classic phishing technique.");

  return sigs;
}

// ── Meta ──────────────────────────────────────────────────────────────
function checkMeta(meta) {
  const sigs = [];
  if (!meta.description && !meta["og:description"])
    sigs.push({ type: "no_meta", category: "content", risk: 10, reason: "No description meta tag", detail: "Hastily-created pages often skip metadata." });
  const og = (meta["og:site_name"] || "").toLowerCase(), ogUrl = meta["og:url"] || "";
  if (og && ogUrl) try { if (!new URL(ogUrl).hostname.includes(og.replace(/\s+/g, "")))
    sigs.push({ type: "og_mismatch", category: "content", risk: 25, reason: `OG name "${og}" doesn't match URL`, detail: "Scammers copy metadata from legitimate sites." }); } catch {}
  return sigs;
}

// ── DOM: Forms ────────────────────────────────────────────────────────
function checkForms(forms, host) {
  if (!forms?.length) return [];
  const sigs = [];
  for (const f of forms) {
    if (f.actionHost && !f.actionHost.includes(host) && !host.includes(f.actionHost))
      sigs.push({ type: "cross_origin_form", category: "forms", risk: 85, reason: `Form sends data to ${f.actionHost}`, detail: "Form data going to a different domain is a credential harvesting technique." });
    if (f.hasPassword && ![...KNOWN_LOGIN].some(p => host === p || host.endsWith("." + p)))
      sigs.push({ type: "unexpected_password", category: "forms", risk: 70, reason: "Password input on non-login site", detail: "Scammers create fake login pages on unrelated domains." });
    if (f.hiddenInputCount > 3)
      sigs.push({ type: "hidden_inputs", category: "forms", risk: 50, reason: `${f.hiddenInputCount} hidden input fields`, detail: "Excessive hidden fields often collect data you didn't provide." });
  }
  return sigs;
}

// ── DOM: Iframes ──────────────────────────────────────────────────────
function checkIframes(iframes) {
  if (!iframes?.length) return [];
  const sigs = [];
  for (const f of iframes) {
    if (f.isHidden)
      sigs.push({ type: "hidden_iframe", category: "forms", risk: 75, reason: "Hidden iframe loading external content", detail: "Invisible iframes load phishing forms or malicious scripts without your knowledge." });
    if (f.isCrossOrigin && !f.isHidden && !KNOWN_EMBEDS.some(d => (f.src || "").includes(d)))
      sigs.push({ type: "unknown_iframe", category: "forms", risk: 35, reason: "Embeds content from unknown domain", detail: "Scammers use cross-origin iframes to inject malicious content." });
  }
  return sigs;
}

// ── DOM: Scripts ──────────────────────────────────────────────────────
function checkScripts(info) {
  if (!info) return [];
  const sigs = [];
  const r = (type, risk, reason, detail) => sigs.push({ type, category: "behavior", risk, reason, detail });
  if (info.hasJsFuck) r("jsfuck", 80, "JSFuck obfuscation detected", "Code hidden using only []+!() — almost exclusively malicious.");
  if (info.hasEvalAtob) r("eval_atob", 75, "Decodes and executes hidden code", "eval(atob(...)) hides malicious payloads from static analysis.");
  if (info.blocksRightClick) r("blocks_right_click", 55, "Right-click disabled", "Scammers prevent inspection of their page.");
  if (info.blocksDevTools) r("blocks_devtools", 60, "Developer tools blocked", "No legitimate site needs to block your browser's built-in tools.");
  if (info.hasCryptoMiner) r("crypto_miner", 85, "Cryptocurrency mining code found", "This page mines crypto using your CPU without consent.");
  if (info.inlineScriptCount > 15) r("excessive_scripts", 40, `${info.inlineScriptCount} inline scripts`, "Unusually high script count suggests obfuscated code.");
  return sigs;
}

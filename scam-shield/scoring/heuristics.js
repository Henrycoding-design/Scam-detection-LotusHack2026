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
      "Scammers register domains like 'paypa1.com' or 'g00gle.com' — replacing letters with similar-looking numbers. At a glance, especially on mobile screens, these look identical to the real site. This is one of the oldest and most effective phishing tricks. Always double-check the exact spelling of the domain before entering any information.");

  if (parts.length > 4)
    r("excessive_subdomains", 35, `Unusual subdomain depth (${parts.length} levels)`,
      "Legitimate websites rarely use more than 2-3 subdomain levels. Scammers stack subdomains like 'secure.login.paypal.evil-site.com' to trick you — your eye catches 'paypal' and assumes it's real, but the actual domain is the last two parts before the slash. Always read a URL from right to left: the real domain is always the last two parts.");

  const tlds = [".xyz",".top",".click",".loan",".tk",".ml",".cc",".biz",".buzz",".surf",".cam",".monster"];
  if (tlds.some(t => h.endsWith(t)))
    r("suspicious_tld", 30, `Suspicious TLD: .${h.split(".").pop()}`,
      "Cheap or free top-level domains like .xyz, .top, and .tk are disproportionately used by scammers because they cost almost nothing to register. While some legitimate startups use these TLDs, the vast majority of phishing pages are hosted on them. Combined with other warning signs, a suspicious TLD is a strong indicator of a scam.");

  const brands = ["paypal","amazon","google","apple","microsoft","netflix","chase","bank","secure","verify","login"];
  const brand = brands.find(b => h.includes(b));
  if (brand && pageHost && !h.includes(pageHost.split(".")[0]))
    r("brand_impersonation_link", 55, `Link impersonates "${brand}"`,
      `This link contains the word '${brand}' in its URL, but it doesn't actually belong to ${brand}. Scammers create URLs like '${brand}-secure-login.com' or '${brand}-verify.net' to trick you into thinking you're on the official site. The real ${brand} website uses '${brand}.com' — anything else should be treated with extreme suspicion. This technique is responsible for billions of dollars in phishing losses annually.`);
  else if (brand && !pageHost && !h.endsWith(`${brand}.com`) && !h.endsWith(`${brand}.net`))
    r("brand_impersonation_page", 60, `Domain impersonates "${brand}"`,
      `This website's domain contains '${brand}' but isn't the official ${brand}.com site. Scammers register lookalike domains to steal login credentials and personal information. When you type your password into a fake login page, the scammer immediately gets access to your real account. Always verify the exact domain before logging in anywhere.`);

  if (h.split("-").length > 3) r("many_dashes", 25, "Domain has many dashes",
    "Scammers use long hyphenated domains like 'secure-update-my-account.com' to cram in keywords that make the URL look official and relevant to what you're searching for. Real companies almost never use more than one dash in their domain name. The more dashes, the more suspicious.");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) r("ip_address_host", 60, "Link uses raw IP address",
    "Instead of a normal domain name like google.com, this link goes directly to a raw IP address like 192.168.1.1. Legitimate websites almost never use IP addresses directly — this is a common technique used by scammers hosting temporary phishing pages on compromised servers. Once the server is taken down, the evidence disappears.");
  if (["bit.ly","tinyurl.com","t.co","ow.ly","rb.gy","cutt.ly","is.gd"].some(s => h.endsWith(s)))
    r("url_shortener", 20, "URL shortener hides destination",
      "This link uses a URL shortening service, which completely hides where the link actually goes. Scammers abuse shorteners to mask dangerous URLs — you click thinking it's one website, but you're sent somewhere completely different. Before clicking any shortened link, use a URL expander tool to preview the real destination.");

  return sigs;
}

// ── Text ──────────────────────────────────────────────────────────────
function checkText(text, title) {
  const t = `${title} ${text}`.toLowerCase(), sigs = [];
  const r = (type, risk, reason, detail) => sigs.push({ type, category: "content", risk, reason, detail });

  const urgency = [...new Set((t.match(/urgent|immediate action|account suspended|verify your account|security alert|action required|claim your prize/gi) || []).map(m => m.toLowerCase()))];
  if (urgency.length >= 2)
    r("urgency_language", 40, "Multiple urgency/fear tactics detected",
      `This page uses multiple pressure phrases like "${urgency.join('", "')}" to create a false sense of urgency. This is a deliberate psychological manipulation technique — scammers know that when people feel panicked or rushed, they make bad decisions without thinking critically. Real companies give you time to verify issues through their official apps or websites. They don't bombard you with multiple urgent warnings on a single page.`);
  else if (urgency.length === 1)
    r("urgency_language_mild", 20, "Urgency language detected",
      `This page uses the phrase "${urgency[0]}" to pressure you into acting quickly. While urgency language isn't always malicious, scammers rely on it heavily to bypass your critical thinking. Before acting on any urgent request, close the page and go directly to the official website or app to verify if there's actually an issue.`);

  if (/seed phrase|recovery phrase|wallet connect|airdrop|double your crypto|giveaway/i.test(t))
    r("crypto_scam", 50, "Crypto/giveaway scam keywords detected",
      "This page mentions cryptocurrency giveaways, seed phrases, or doubling your crypto. These are hallmarks of scams that have stolen billions of dollars. No legitimate service will ever ask for your seed/recovery phrase — anyone who has it can drain your entire wallet. 'Send 1 ETH to get 2 back' is ALWAYS a scam. Even Elon Musk impersonation giveaways on social media use this exact technique to steal crypto.");

  if (/social security|credit card number|routing number|wire transfer|enter your password/i.test(t))
    r("sensitive_data_request", 45, "Requests highly sensitive personal info",
      "This page asks for extremely sensitive information like Social Security numbers, credit card details, or passwords. Legitimate websites handle these requests through secure, verified channels — not through random web pages. If you didn't initiate this request yourself by going directly to an official website, do not enter any personal data. Identity thieves use fake forms to collect this information and open accounts in your name.");

  return sigs;
}

// ── Links ─────────────────────────────────────────────────────────────
function checkLinks(links, host) {
  const sigs = [];
  const r = (type, risk, reason, detail) => sigs.push({ type, category: "links", risk, reason, detail });
  const isExternal = l => { try { return !new URL(l.href).hostname.includes(host); } catch { return false; } };

  const ext = links.filter(isExternal);
  if (links.length >= 3 && ext.length / links.length > 0.7)
    r("high_external_ratio", 35, `${Math.round(ext.length/links.length*100)}% of links go to external domains`,
      "Almost all the links on this page lead to other websites instead of staying on the same domain. Legitimate websites keep most links internal — to their own products, help pages, and resources. A page that primarily exists to send you elsewhere is called a 'link farm' or redirect page, and scammers use them to funnel traffic to phishing sites, malware downloads, or scam offers. Treat any page that sends you somewhere else with suspicion.");

  const loginLinks = links.filter(l => l.hasLoginKeyword && isExternal(l));
  if (loginLinks.length)
    r("offsite_login_link", 50, `${loginLinks.length} login link(s) pointing elsewhere`,
      "This page contains links with words like 'login', 'sign in', or 'verify' that send you to a completely different website. This is a classic phishing technique — the page looks like it belongs to one company, but clicking the login button takes you to a fake page designed to steal your credentials. Always check where a link actually goes before clicking (hover over it to see the real URL in the bottom-left of your browser).");

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
      sigs.push({ type: "cross_origin_form", category: "forms", risk: 85,
        reason: `Form sends data to ${f.actionHost}`,
        detail: `This page contains a form that sends your information to a completely different website (${f.actionHost}). Legitimate websites always process form data on their own servers. When a form sends data to an external domain, whatever you type — passwords, credit card numbers, personal details — goes directly to the scammer. This is one of the most direct and effective credential harvesting techniques in existence.` });
    if (f.hasPassword && ![...KNOWN_LOGIN].some(p => host === p || host.endsWith("." + p)))
      sigs.push({ type: "unexpected_password", category: "forms", risk: 70,
        reason: "Password input on non-login site",
        detail: `This page asks for a password, but ${host} is not a recognized login service. Scammers create pixel-perfect copies of real login pages — Gmail, Facebook, bank portals — and host them on unrelated domains. When you enter your password, it goes straight to the attacker. Always verify the domain before entering credentials. If you arrived here from an email or message, close this page and go to the real website directly.` });
    if (f.hiddenInputCount > 3)
      sigs.push({ type: "hidden_inputs", category: "forms", risk: 50,
        reason: `${f.hiddenInputCount} hidden input fields`,
        detail: `This form contains ${f.hiddenInputCount} hidden input fields that you cannot see. While one or two hidden fields are normal (like CSRF security tokens), this many suggests the form is collecting extra data about you — tracking identifiers, session tokens, or information scraped from your browser — and bundling it with whatever you do submit. Scammers use this to fingerprint your device and correlate your data across multiple phishing sites.` });
  }
  return sigs;
}

// ── DOM: Iframes ──────────────────────────────────────────────────────
function checkIframes(iframes) {
  if (!iframes?.length) return [];
  const sigs = [];
  for (const f of iframes) {
    if (f.isHidden)
      sigs.push({ type: "hidden_iframe", category: "forms", risk: 75,
        reason: "Hidden iframe loading external content",
        detail: `This page embeds an invisible iframe — a hidden window within the page — that loads content from ${f.src || "an unknown source"}. Hidden iframes are a favorite tool of scammers: they can load phishing forms, tracking pixels, or malicious scripts without you ever knowing. The content exists on the page and can interact with your session, but you can't see it. Legitimate websites have almost no reason to hide iframes.`);
    if (f.isCrossOrigin && !f.isHidden && !KNOWN_EMBEDS.some(d => (f.src || "").includes(d)))
      sigs.push({ type: "unknown_iframe", category: "forms", risk: 35,
        reason: "Embeds content from unknown domain",
        detail: `This page loads an embedded frame from ${f.src || "an external source"} that isn't a recognized embed provider (like YouTube or Google Maps). While embeds are common for videos and maps, scammers use cross-origin iframes to inject phishing forms or malicious content that appears to be part of the legitimate page. The iframe runs in its own security context and could be doing anything behind the scenes.`);
  }
  return sigs;
}

// ── DOM: Scripts ──────────────────────────────────────────────────────
function checkScripts(info) {
  if (!info) return [];
  const sigs = [];
  const r = (type, risk, reason, detail) => sigs.push({ type, category: "behavior", risk, reason, detail });
  if (info.hasJsFuck) r("jsfuck", 80, "JSFuck obfuscation detected",
    "This page contains JavaScript written entirely in JSFuck — an encoding that represents any code using only six characters: []+!(). It's used to hide malicious behavior from security scanners and code reviewers. Legitimate developers never use JSFuck because it makes code unreadable. Its presence is almost always a sign that the page is doing something it doesn't want you to see, like silently redirecting you or stealing data.");
  if (info.hasEvalAtob) r("eval_atob", 75, "Decodes and executes hidden code",
    "This page uses 'eval(atob(...))' — it takes a base64-encoded string, decodes it into JavaScript, and executes it immediately. This is a technique to hide malicious code from static analysis tools. The encoded payload could contain anything: redirects to phishing pages, data exfiltration code, or cryptocurrency miners. Legitimate developers have no reason to hide their code this way.");
  if (info.blocksRightClick) r("blocks_right_click", 55, "Right-click disabled",
    "This page actively prevents you from right-clicking. Scammers do this to stop you from inspecting the page source, checking where links actually go, or opening developer tools. No legitimate website restricts right-clicking — it's a user-hostile behavior that exists almost exclusively on scam pages trying to hide what they're really doing.");
  if (info.blocksDevTools) r("blocks_devtools", 60, "Developer tools blocked",
    "This page tries to detect if you have browser developer tools open and either blocks them or redirects you away. This is a strong anti-analysis technique used by sophisticated scammers to prevent security researchers and tech-savvy users from inspecting the page's behavior. No legitimate website needs to prevent you from using your browser's built-in debugging tools.");
  if (info.hasCryptoMiner) r("crypto_miner", 85, "Cryptocurrency mining code found",
    "This page includes code that hijacks your computer's processor to mine cryptocurrency for the site owner — without your knowledge or consent. Crypto miners drain your battery, slow down your device significantly, and increase your electricity bill. Some malicious sites embed miners directly; others inject them through compromised ad networks. Either way, your hardware is being used to make someone else money.");
  if (info.inlineScriptCount > 15) r("excessive_scripts", 40, `${info.inlineScriptCount} inline scripts`,
    `This page contains ${info.inlineScriptCount} inline JavaScript blocks embedded directly in the HTML. While a few inline scripts are normal, this unusually high number often indicates the page was assembled from copied code snippets or is using multiple obfuscated scripts to distribute malicious behavior across many small pieces that are harder to analyze as a whole.`);
  return sigs;
}

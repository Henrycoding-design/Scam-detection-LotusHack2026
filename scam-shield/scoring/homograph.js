// scoring/homograph.js — Unicode confusable / homograph attack detection

// Subset of Unicode confusables: maps confusable chars to their ASCII equivalent.
// Derived from Unicode Consortium's confusables.txt (https://www.unicode.org/Public/security/latest/confusables.txt)
const CONFUSABLES = {
  // Cyrillic → Latin
  "\u0430": "a", "\u0410": "A", // а, А
  "\u0432": "b", "\u0412": "B", // в, В
  "\u0441": "c", "\u0421": "C", // с, С
  "\u0435": "e", "\u0415": "E", // е, Е
  "\u0444": "f", // ф
  "\u0433": "g", // г (looks like r/g depending on font)
  "\u0456": "i", "\u0406": "I", // і, І
  "\u0458": "j", "\u0408": "J", // ј, Ј
  "\u043a": "k", "\u041a": "K", // к, К
  "\u04cf": "l", // ӏ (palochka)
  "\u043c": "m", "\u041c": "M", // м, М
  "\u043d": "h", "\u041d": "H", // н, Н (looks like H)
  "\u043e": "o", "\u041e": "O", // о, О
  "\u0440": "p", "\u0420": "P", // р, Р
  "\u0441": "c", // с
  "\u0442": "t", "\u0422": "T", // т, Т
  "\u0443": "y", "\u0423": "Y", // у, У
  "\u0445": "x", "\u0425": "X", // х, Х
  "\u0455": "s", // ѕ
  "\u045c": "q", // ќ (loosely)
  "\u0462": "B", // Ѣ (looks like B)
  "\u0472": "F", // Ѳ
  "\u0474": "V", // Ѵ
  "\u0491": "r", // ґ

  // Greek → Latin
  "\u03b1": "a", "\u0391": "A", // α, Α
  "\u03b2": "b", "\u0392": "B", // β, Β
  "\u03b3": "y", // γ
  "\u03b4": "d", // δ
  "\u03b5": "e", "\u0395": "E", // ε, Ε
  "\u03b7": "n", // η (looks like n)
  "\u03b9": "i", "\u0399": "I", // ι, Ι
  "\u03ba": "k", // κ
  "\u03bc": "u", "\u039c": "M", // μ, Μ
  "\u03bd": "v", // ν
  "\u03bf": "o", "\u039f": "O", // ο, Ο
  "\u03c0": "p", // π (loosely)
  "\u03c1": "p", // ρ
  "\u03c3": "s", // σ
  "\u03c4": "t", "\u03a4": "T", // τ, Τ
  "\u03c5": "u", "\u03a5": "Y", // υ, Υ
  "\u03c7": "x", // χ
  "\u03c9": "w", "\u03a9": "W", // ω (loosely)
  "\u0398": "0", // Θ (looks like 0)

  // Common lookalikes
  "\u0251": "a", // ɑ
  "\u0261": "g", // ɡ
  "\u0262": "g", // ɢ
  "\u026a": "i", // ɪ
  "\u026f": "w", // ɯ (loosely)
  "\u0279": "r", // ɹ
  "\u0281": "r", // ʀ
  "\u0283": "s", // ʃ
  "\u028a": "u", // ʊ
  "\u0292": "z", // ʒ

  // Fullwidth (Asian typography)
  "\uff41": "a", "\uff21": "A",
  "\uff42": "b", "\uff22": "B",
  "\uff43": "c", "\uff23": "C",
  "\uff44": "d", "\uff24": "D",
  "\uff45": "e", "\uff25": "E",
  "\uff46": "f", "\uff26": "F",
  "\uff47": "g", "\uff27": "G",
  "\uff48": "h", "\uff28": "H",
  "\uff49": "i", "\uff29": "I",
  "\uff4a": "j", "\uff2a": "J",
  "\uff4b": "k", "\uff2b": "K",
  "\uff4c": "l", "\uff2c": "L",
  "\uff4d": "m", "\uff2d": "M",
  "\uff4e": "n", "\uff2e": "N",
  "\uff4f": "o", "\uff2f": "O",
  "\uff50": "p", "\uff30": "P",
  "\uff51": "q", "\uff31": "Q",
  "\uff52": "r", "\uff32": "R",
  "\uff53": "s", "\uff33": "S",
  "\uff54": "t", "\uff34": "T",
  "\uff55": "u", "\uff35": "U",
  "\uff56": "v", "\uff36": "V",
  "\uff57": "w", "\uff37": "W",
  "\uff58": "x", "\uff38": "X",
  "\uff59": "y", "\uff39": "Y",
  "\uff5a": "z", "\uff3a": "Z",

  // Digit lookalikes
  "\uff10": "0", "\uff11": "1", "\uff12": "2", "\uff13": "3", "\uff14": "4",
  "\uff15": "5", "\uff16": "6", "\uff17": "7", "\uff18": "8", "\uff19": "9",
  "\u0430" /* already mapped */: "a",

  // Misc confusables
  "\u2027": ".", // hyphenation point
  "\ufe52": ".", // small full stop
  "\uff0e": ".", // fullwidth full stop
  "\u02d0": ":", // modifier letter triangular colon
  "\ufe55": ":", // small colon
  "\uff1a": ":", // fullwidth colon
  "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
  "\u2015": "-", "\u2212": "-", "\ufe58": "-", "\ufe63": "-", "\uff0d": "-",
  "\u2043": "-", // hyphen bullet
};

// Known brands to check against after normalization
const KNOWN_BRANDS = [
  "paypal", "amazon", "google", "apple", "microsoft", "netflix", "facebook",
  "instagram", "twitter", "linkedin", "github", "dropbox", "icloud",
  "chase", "wellsfargo", "bankofamerica", "citibank", "capitalone",
  "stripe", "square", "coinbase", "binance", "metamask", "opensea",
  "steam", "epicgames", "roblox", "discord", "telegram", "whatsapp",
  "zoom", "slack", "notion", "figma", "adobe", "spotify", "hulu",
  "dhl", "fedex", "ups", "usps", "ebay", "walmart", "target",
  "venmo", "zelle", "cashapp", "revolut", "wise",
];

function normalizeConfusables(text) {
  let result = "";
  for (const char of text) {
    result += CONFUSABLES[char] || char;
  }
  return result;
}

function hasNonAscii(text) {
  for (const char of text) {
    if (char.charCodeAt(0) > 127) return true;
  }
  return false;
}

function getScripts(text) {
  const scripts = new Set();
  for (const char of text) {
    const code = char.charCodeAt(0);
    if (code <= 0x007F) scripts.add("Latin");
    else if (code >= 0x0400 && code <= 0x04FF) scripts.add("Cyrillic");
    else if (code >= 0x0370 && code <= 0x03FF) scripts.add("Greek");
    else if (code >= 0xFF00 && code <= 0xFFEF) scripts.add("Fullwidth");
    else if (code >= 0x0600 && code <= 0x06FF) scripts.add("Arabic");
    else if (code >= 0x0900 && code <= 0x097F) scripts.add("Devanagari");
    else if (code > 0x007F) scripts.add("Other");
  }
  return scripts;
}

export function detectHomograph(url) {
  const signals = [];

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;

    // Skip pure ASCII hostnames — no homograph possible
    if (!hasNonAscii(hostname)) return signals;

    // Check 1: Mixed scripts in hostname (e.g., "gооgle.com" with Cyrillic о)
    const labels = hostname.split(".");
    for (const label of labels) {
      const scripts = getScripts(label);
      if (scripts.size > 1 && !scripts.has("Fullwidth")) {
        signals.push({
          type: "mixed_script_hostname",
          risk: 90,
          reason: "Domain mixes different writing systems (e.g., Latin + Cyrillic)",
          detail: `The domain label "${label}" contains characters from multiple scripts: ${[...scripts].join(", ")}. This is a technique called a homograph attack — scammers register domains using lookalike characters from other alphabets (like Cyrillic 'а' which looks identical to Latin 'a') to impersonate legitimate websites. Your browser may display this domain as if it were a normal English URL, making it nearly impossible to spot the fraud without technical inspection.`,
        });
        break;
      }
    }

    // Check 2: Normalization reveals known brand impersonation
    const normalized = normalizeConfusables(hostname);
    const normalizedLower = normalized.toLowerCase();
    for (const brand of KNOWN_BRANDS) {
      if (normalizedLower.includes(brand) && !hostname.toLowerCase().includes(brand)) {
        signals.push({
          type: "homograph_brand_impersonation",
          risk: 95,
          reason: `Domain uses lookalike characters to impersonate "${brand}"`,
          detail: `After normalizing confusable characters, this domain resolves to something containing "${brand}" — but the actual characters used are lookalikes from a different alphabet. This is a homograph attack designed to impersonate ${brand}. Even though the URL looks correct in your browser's address bar, it's actually a completely different domain. Never trust a URL that uses non-standard characters, and always verify you're on the official ${brand}.com website.`,
        });
        break;
      }
    }

    // Check 3: Non-ASCII in hostname (even without brand match)
    if (signals.length === 0) {
      signals.push({
        type: "non_ascii_hostname",
        risk: 60,
        reason: "Domain contains non-standard characters",
        detail: `This domain uses international characters (IDN / Internationalized Domain Name). While many IDN domains are legitimate (especially non-Latin language websites), scammers exploit IDN to create lookalike domains. If you expected to visit an English-language website, this is a strong warning sign.`,
      });
    }
  } catch {
    // Invalid URL
  }

  return signals;
}

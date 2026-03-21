// scoring/homograph.js — Lean Unicode homograph detection

const BRANDS = [
  "paypal", "amazon", "google", "apple", "microsoft", "netflix", "facebook",
  "instagram", "linkedin", "github", "chase", "wellsfargo", "bankofamerica",
  "coinbase", "binance", "discord", "telegram", "whatsapp", "steam", "ebay",
];

// ~20 highest-impact Cyrillic/Greek confusables (pixel-identical to Latin)
const CONF = {
  "\u0430":"a","\u0432":"b","\u0441":"c","\u0435":"e","\u0433":"g",
  "\u0456":"i","\u0458":"j","\u043a":"k","\u04cf":"l","\u043c":"m",
  "\u043d":"h","\u043e":"o","\u0440":"p","\u0442":"t","\u0443":"y",
  "\u0445":"x","\u0455":"s","\u0491":"r",
  "\u03b1":"a","\u03b2":"b","\u03b5":"e","\u03b9":"i","\u03ba":"k",
  "\u03bd":"v","\u03bf":"o","\u03c1":"p","\u03c3":"s","\u03c4":"t",
};

export function detectHomograph(url) {
  try {
    const host = new URL(url).hostname;
    if (!/[^\x00-\x7F]/.test(host)) return [];

    const signals = [];
    const hasLatin = /[\u0041-\u007A]/.test(host);
    const hasCyrillic = /[\u0400-\u04FF]/.test(host);
    const hasGreek = /[\u0370-\u03FF]/.test(host);

    if (hasLatin && (hasCyrillic || hasGreek)) {
      signals.push({
        type: "mixed_script_hostname", category: "domain", risk: 90,
        reason: "Domain mixes different writing systems (e.g., Latin + Cyrillic)",
        detail: "This domain uses lookalike characters from another alphabet to impersonate a real website. Your browser may display it as a normal English URL, but it's actually a different domain. This is called a homograph attack.",
      });
    }

    // Normalize confusables → check for brand impersonation
    const normalized = [...host].map(c => CONF[c] || c).join("").toLowerCase();
    for (const brand of BRANDS) {
      if (normalized.includes(brand) && !host.toLowerCase().includes(brand)) {
        signals.push({
          type: "homograph_brand", category: "domain", risk: 95,
          reason: `Domain uses lookalike characters to impersonate "${brand}"`,
          detail: `After normalizing characters, this domain contains "${brand}" — but uses lookalike letters from another alphabet. This is a homograph attack impersonating ${brand}.`,
        });
        break;
      }
    }

    if (!signals.length) {
      signals.push({
        type: "non_ascii_hostname", category: "domain", risk: 50,
        reason: "Domain contains international characters",
        detail: "This domain uses international characters (IDN). While some IDN domains are legitimate, scammers use them to create lookalike domains.",
      });
    }

    return signals;
  } catch { return []; }
}

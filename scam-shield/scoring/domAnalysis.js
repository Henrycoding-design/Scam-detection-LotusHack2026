// scoring/domAnalysis.js — DOM-level phishing detection

// Known legitimate login providers that are expected to have credential forms
const KNOWN_LOGIN_PROVIDERS = [
  "google.com", "accounts.google.com", "mail.google.com",
  "facebook.com", "login.facebook.com",
  "apple.com", "appleid.apple.com", "icloud.com",
  "microsoft.com", "login.microsoftonline.com", "live.com", "outlook.com",
  "amazon.com", "signin.amazon.com",
  "paypal.com",
  "netflix.com",
  "twitter.com", "x.com",
  "linkedin.com",
  "github.com",
  "dropbox.com",
  "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
  "instagram.com",
  "discord.com",
  "reddit.com",
  "yahoo.com", "login.yahoo.com",
  "steamcommunity.com", "store.steampowered.com",
  "ebay.com",
  "spotify.com",
];

function isKnownLoginProvider(hostname) {
  return KNOWN_LOGIN_PROVIDERS.some(
    (provider) => hostname === provider || hostname.endsWith("." + provider)
  );
}

export function checkForms(formInfo, hostname) {
  const signals = [];

  if (!formInfo || formInfo.length === 0) return signals;

  for (const form of formInfo) {
    // Cross-origin form action — form data sent to a different domain
    if (form.actionHost && !form.actionHost.includes(hostname) && !hostname.includes(form.actionHost)) {
      signals.push({
        type: "cross_origin_form",
        risk: 85,
        reason: `Form sends data to external domain: ${form.actionHost}`,
        detail: `This page contains a form that submits your information to a different website (${form.actionHost}). Legitimate websites process form data on their own servers — submitting data to a third-party domain is a classic credential harvesting technique. If you entered a password or personal info into this form, it was likely sent to a scammer.`,
      });
    }

    // Password field on a non-login provider — suspicious
    if (form.hasPassword && !isKnownLoginProvider(hostname)) {
      signals.push({
        type: "unexpected_password_form",
        risk: 70,
        reason: "Password input on a page that isn't a known login provider",
        detail: `This page asks for a password, but ${hostname} is not a recognized login service. Scammers create fake login pages that look identical to real ones (like a fake Gmail login page hosted on an unrelated domain). Always check that you're entering passwords only on the official website you intended to visit.`,
      });
    }

    // Hidden inputs collecting data
    if (form.hiddenInputCount > 3) {
      signals.push({
        type: "excessive_hidden_inputs",
        risk: 50,
        reason: `Form has ${form.hiddenInputCount} hidden input fields`,
        detail: `This form contains ${form.hiddenInputCount} hidden input fields that you can't see. While some hidden fields are normal (like CSRF tokens), an excessive number often indicates the form is collecting tracking data or preparing to submit information you didn't explicitly provide. Scammers use hidden fields to bundle extra data with your form submission.`,
      });
    }
  }

  return signals;
}

export function checkIframes(iframeInfo) {
  const signals = [];

  if (!iframeInfo || iframeInfo.length === 0) return signals;

  for (const iframe of iframeInfo) {
    // Hidden iframes — used to load malicious content invisibly
    if (iframe.isHidden) {
      signals.push({
        type: "hidden_iframe",
        risk: 75,
        reason: "Page contains hidden iframe loading external content",
        detail: `This page embeds an invisible iframe (a hidden window within the page) that loads content from ${iframe.src || "an unknown source"}. Hidden iframes are commonly used by scammers to load phishing forms, tracking pixels, or malicious scripts without the user's knowledge. Legitimate websites rarely need to hide iframes.`,
      });
    }

    // Cross-origin iframe
    if (iframe.isCrossOrigin && !iframe.isHidden) {
      // Lower risk if visible — could be legitimate embed (YouTube, etc.)
      // Only flag if not from known embed providers
      const knownEmbeds = ["youtube.com", "youtube-nocookie.com", "player.vimeo.com",
        "maps.google.com", "open.spotify.com", "embedly.com", "cdn.embedly.com"];
      const isKnown = knownEmbeds.some((d) => (iframe.src || "").includes(d));
      if (!isKnown) {
        signals.push({
          type: "cross_origin_iframe",
          risk: 35,
          reason: "Page embeds content from an unknown external domain",
          detail: `This page loads an embedded frame from ${iframe.src || "an external source"}. While embeds are common (like YouTube videos), scammers use them to inject phishing forms or malicious content that appears to be part of the legitimate page. Verify that any embedded content comes from a source you trust.`,
        });
      }
    }
  }

  return signals;
}

export function checkScripts(scriptInfo) {
  const signals = [];

  if (!scriptInfo) return signals;

  // JSFuck / heavy obfuscation — code that's only []+${}() patterns
  if (scriptInfo.hasJsFuck) {
    signals.push({
      type: "jsfuck_obfuscation",
      risk: 80,
      reason: "Page uses JSFuck obfuscation to hide malicious code",
      detail: "This page contains JavaScript written in JSFuck — an obfuscation technique that encodes arbitrary code using only six characters: []+!(). This is used to hide malicious behavior from security scanners and code reviewers. Legitimate websites almost never use JSFuck. Its presence is a strong indicator that the page is trying to conceal what it actually does.",
    });
  }

  // eval(atob(...)) pattern — decode and execute base64
  if (scriptInfo.hasEvalAtob) {
    signals.push({
      type: "eval_atob_chain",
      risk: 75,
      reason: "Page decodes and executes hidden code (eval + base64)",
      detail: "This page uses 'eval(atob(...))' — it takes a base64-encoded string, decodes it, and executes it as JavaScript. This is a common technique to hide malicious code from static analysis. The encoded payload could contain redirects, data exfiltration, or other harmful actions. Legitimate developers almost never need to hide their code this way.",
    });
  }

  // Right-click / devtools disabling
  if (scriptInfo.blocksRightClick) {
    signals.push({
      type: "blocks_right_click",
      risk: 55,
      reason: "Page disables right-click context menu",
      detail: "This page actively prevents you from right-clicking. Scammers do this to stop you from inspecting the page's source code, checking link destinations, or using browser developer tools. Legitimate websites rarely restrict right-clicking — this is almost exclusively a scam technique to hide what the page is really doing.",
    });
  }

  // DevTools detection / blocking
  if (scriptInfo.blocksDevTools) {
    signals.push({
      type: "blocks_devtools",
      risk: 60,
      reason: "Page detects and blocks browser developer tools",
      detail: "This page tries to detect if you have browser developer tools open and either blocks them or redirects you away. This is a strong anti-analysis technique used by scammers to prevent security researchers and tech-savvy users from inspecting the page. No legitimate website needs to prevent you from using your browser's built-in tools.",
    });
  }

  // Crypto miner detection
  if (scriptInfo.hasCryptoMiner) {
    signals.push({
      type: "crypto_miner",
      risk: 85,
      reason: "Page contains cryptocurrency mining code",
      detail: "This page includes code that uses your computer's processor to mine cryptocurrency for the site owner — without your knowledge or consent. This drains your battery, slows down your device, and increases your electricity bill. Some sites that do this are outright malicious; others bundle miners in their ad networks.",
    });
  }

  // Excessive inline scripts (potential obfuscation)
  if (scriptInfo.inlineScriptCount > 15) {
    signals.push({
      type: "excessive_inline_scripts",
      risk: 40,
      reason: `Page has ${scriptInfo.inlineScriptCount} inline script blocks`,
      detail: `This page contains ${scriptInfo.inlineScriptCount} inline JavaScript blocks. While some inline scripts are normal, this unusually high number often indicates a page assembled from copied code or one using multiple obfuscated scripts to hide malicious behavior. Legitimate websites typically use external script files for maintainability.`,
    });
  }

  return signals;
}

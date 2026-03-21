// content/scanner.js

if (window.ScamShieldScannerReady) {
  // Already injected — skip
} else {

const ScamShieldScanner = (() => {
  let localRiskMap = {};
  let lastFingerprint = "";
  let debounceTimer = null;
  let isScanning = false;
  let lastPageResult = null;
  let lastVerdict = "";
  let bannerDismissed = false;

  function normalizeUrl(url) {
    try {
      const parsed = new URL(url);
      parsed.hash = "";
      return parsed.toString();
    } catch {
      return url;
    }
  }

  function buildFingerprint(context) {
    const text = (context.visibleText || "").slice(0, 400);
    const links = (context.links || [])
      .slice(0, 10)
      .map((link) => normalizeUrl(link.href))
      .join("|");
    return `${normalizeUrl(context.url)}::${context.title}::${text}::${links}`;
  }

  function extractPageContext() {
    return {
      url: normalizeUrl(window.location.href),
      title: document.title,
      meta: extractMeta(),
      links: extractLinks(),
      visibleText: extractVisibleText(),
      formInfo: extractFormInfo(),
      iframeInfo: extractIframeInfo(),
      scriptInfo: extractScriptInfo(),
      timestamp: Date.now(),
    };
  }

  function extractMeta() {
    const tags = {};
    document.querySelectorAll("meta").forEach((el) => {
      const name = el.getAttribute("name") || el.getAttribute("property");
      const content = el.getAttribute("content");
      if (name && content) tags[name] = content;
    });
    return tags;
  }

  function extractLinks() {
    return Array.from(document.querySelectorAll("a[href]"))
      .map((el) => ({
        href: normalizeUrl(el.href),
        text: el.innerText.trim().slice(0, 120),
        isVisible: isElementVisible(el),
        hasLoginKeyword: /log.?in|sign.?in|password|verify/i.test(el.innerText),
      }))
      .filter((link) => link.href.startsWith("http"))
      .slice(0, 80);
  }

  function extractVisibleText() {
    if (!document.body) return "";

    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const parent = node.parentElement;
          if (!parent) return NodeFilter.FILTER_REJECT;
          if (["SCRIPT", "STYLE", "NOSCRIPT"].includes(parent.tagName)) {
            return NodeFilter.FILTER_REJECT;
          }
          if (!isElementVisible(parent)) return NodeFilter.FILTER_REJECT;
          return node.textContent.trim()
            ? NodeFilter.FILTER_ACCEPT
            : NodeFilter.FILTER_REJECT;
        },
      }
    );

    const chunks = [];
    let node;
    let currentLength = 0;

    while ((node = walker.nextNode()) && currentLength < 3000) {
      const text = node.textContent.trim();
      if (!text) continue;
      chunks.push(text);
      currentLength += text.length + 1;
    }

    return chunks.join(" ");
  }

  function extractFormInfo() {
    const forms = [];
    const hostname = window.location.hostname;
    document.querySelectorAll("form").forEach((form) => {
      let actionHost = "";
      try { actionHost = form.action ? new URL(form.action).hostname : ""; } catch {}

      forms.push({
        actionHost,
        hasPassword: !!form.querySelector('input[type="password"]'),
        hiddenInputCount: form.querySelectorAll('input[type="hidden"]').length,
      });
    });

    // Also check for password inputs outside of <form> elements
    const loosePasswords = document.querySelectorAll('input[type="password"]');
    if (loosePasswords.length > 0 && forms.length === 0) {
      forms.push({
        actionHost: "",
        hasPassword: true,
        hiddenInputCount: 0,
      });
    }

    return forms;
  }

  function extractIframeInfo() {
    const iframes = [];
    document.querySelectorAll("iframe").forEach((iframe) => {
      const style = window.getComputedStyle(iframe);
      const isHidden =
        style.display === "none" ||
        style.visibility === "hidden" ||
        style.opacity === "0" ||
        iframe.width === "0" ||
        iframe.height === "0" ||
        iframe.offsetWidth === 0 ||
        iframe.offsetHeight === 0;

      let isCrossOrigin = false;
      try {
        if (iframe.src) {
          isCrossOrigin = new URL(iframe.src).hostname !== window.location.hostname;
        }
      } catch {}

      iframes.push({
        src: iframe.src || "",
        isHidden,
        isCrossOrigin,
      });
    });
    return iframes;
  }

  function extractScriptInfo() {
    const scripts = document.querySelectorAll("script");
    let inlineCount = 0;
    let hasJsFuck = false;
    let hasEvalAtob = false;
    let blocksRightClick = false;
    let blocksDevTools = false;
    let hasCryptoMiner = false;

    scripts.forEach((script) => {
      const src = script.src || "";
      const content = script.textContent || "";

      if (!src) inlineCount++;

      // JSFuck: code that's almost entirely []+!()
      if (content.length > 200 && /^[\[\]\+\!\(\)\s]+$/.test(content.slice(0, 500))) {
        hasJsFuck = true;
      }

      // eval(atob(...))
      if (/eval\s*\(\s*atob\s*\(/.test(content)) {
        hasEvalAtob = true;
      }

      // Right-click disabling
      if (/addEventListener\s*\(\s*['"]contextmenu['"]/.test(content) && /preventDefault/.test(content)) {
        blocksRightClick = true;
      }

      // DevTools blocking
      if (/F12|devtools|debugger\s*;?\s*\}/.test(content) || /keydown.*F12/i.test(content)) {
        blocksDevTools = true;
      }

      // Crypto miner indicators
      if (/coinhive|crypto-loot|coinimp|minexmr|webassembly.*mine|wss:.*pool/i.test(content + src)) {
        hasCryptoMiner = true;
      }
    });

    // Also check inline event handlers for right-click blocking
    if (!blocksRightClick && document.documentElement.outerHTML.includes('oncontextmenu')) {
      blocksRightClick = true;
    }

    return {
      inlineScriptCount: inlineCount,
      hasJsFuck,
      hasEvalAtob,
      blocksRightClick,
      blocksDevTools,
      hasCryptoMiner,
    };
  }

  function isElementVisible(el) {
    const style = window.getComputedStyle(el);
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      style.opacity !== "0" &&
      el.offsetWidth > 0 &&
      el.offsetHeight > 0
    );
  }

  function sendToBackground(message) {
    try {
      return chrome.runtime.sendMessage(message).catch((err) => {
        if (err && err.message && !err.message.includes("Extension context invalidated")) {
          console.warn("[ScamShield] Message error:", err);
        }
        return null;
      });
    } catch (err) {
      if (err && err.message && !err.message.includes("Extension context invalidated")) {
        console.warn("[ScamShield] Send error:", err);
      }
      return Promise.resolve(null);
    }
  }

  async function runScan(type) {
    if (isScanning) return;
    if (!document.body) return;

    const context = extractPageContext();
    const fingerprint = buildFingerprint(context);
    if (fingerprint === lastFingerprint) return;

    isScanning = true;
    lastFingerprint = fingerprint;

    try {
      await sendToBackground({ type, context });
    } finally {
      isScanning = false;
    }
  }

  function startMutationWatcher() {
    if (!document.body) return;

    const observer = new MutationObserver((mutations) => {
      const meaningful = mutations.some(
        (mutation) => mutation.type === "childList" && mutation.addedNodes.length > 0
      );
      if (!meaningful) return;

      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        runScan("PAGE_UPDATED");
      }, 400);
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  function openSidePanel() {
    sendToBackground({ type: "OPEN_SIDE_PANEL" });
  }

  function syncPageWarnings(result) {
    lastPageResult = result;

    // Reset dismissal flag when the verdict changes
    if (result?.verdict !== lastVerdict) {
      bannerDismissed = false;
      lastVerdict = result?.verdict || "";
    }

    if (!window.ScamShieldUI) return;

    if (!result || result.verdict === "safe" || result.verdict === "not_scannable") {
      window.ScamShieldUI.removeWarningUI();
      bannerDismissed = false;
      return;
    }

    if (result.verdict === "suspicious") {
      if (bannerDismissed) return;
      window.ScamShieldUI.showSuspiciousBanner({
        score: result.score,
        onOpenPanel: openSidePanel,
        onDismiss: () => { bannerDismissed = true; },
      });
      return;
    }

    window.ScamShieldUI.showDangerOverlay({
      href: result.url,
      score: result.score,
      reason: result.explanation?.reason || result.reasons?.[0] || "",
      onProceed: () => {
        window.ScamShieldUI.removeWarningUI();
      },
    });
  }

  function attachClickInterceptor() {
    document.addEventListener(
      "click",
      (event) => {
        const anchor = event.target.closest("a[href]");
        if (!anchor) return;

        const href = normalizeUrl(anchor.href);
        if (!href.startsWith("http")) return;

      const score = localRiskMap[href] ?? 100;
      if (score > 30) return;

        event.preventDefault();
        event.stopPropagation();

        if (anchor.target === "_blank") {
          anchor.rel = "noopener noreferrer";
        }

        window.ScamShieldUI?.showDangerOverlay({
          href,
          score,
          reason: lastPageResult?.explanation?.reason || lastPageResult?.reasons?.[0] || "",
          onProceed: () => {
            if (anchor.target === "_blank") {
              window.open(href, "_blank", "noopener,noreferrer");
            } else {
              window.location.href = href;
            }
          },
        });
      },
      true
    );
  }

  function handleRuntimeMessage(message) {
    if (message.type === "LINK_RISK_MAP") {
      localRiskMap = { ...(message.linkRiskMap || {}) };
    }

    if (message.type === "SCAN_STAGE_HEURISTIC") {
      syncPageWarnings(message.result);
      lastFingerprint = buildFingerprint(extractPageContext());
    }

    if (message.type === "SCAN_STAGE_AI") {
      syncPageWarnings(message.result);
      lastFingerprint = buildFingerprint(extractPageContext());

      const overlay = document.getElementById("scamshield-danger-overlay");
      const reasonEl = overlay?.querySelector("#ss-danger-reason");
      if (reasonEl && message.result?.explanation?.reason) {
        reasonEl.textContent = message.result.explanation.reason;
      }
    }
  }

  async function restoreSessionState() {
    try {
      const { activeTabId } = await chrome.storage.session.get("activeTabId");
      if (!activeTabId) return;

      const key = `scanResult_${activeTabId}`;
      const { [key]: result } = await chrome.storage.session.get(key);
      if (!result) return;

      const currentUrl = normalizeUrl(window.location.href);
      if (result.url !== currentUrl) return;

      lastFingerprint = buildFingerprint(extractPageContext());
      localRiskMap = result.linkRiskMap || {};
      syncPageWarnings(result);
    } catch {
      // Session storage may be unavailable
    }
  }

  async function init() {
    await restoreSessionState();
    chrome.runtime.onMessage.addListener(handleRuntimeMessage);
    attachClickInterceptor();
    startMutationWatcher();
    window.ScamShieldScannerReady = true;
    runScan("PAGE_LOADED");
  }

  return { init };
})();

ScamShieldScanner.init();

} // end double-init guard

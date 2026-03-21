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
    const text = context.visibleText || "";
    const links = (context.links || []).map((link) => normalizeUrl(link.href)).join("|");
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
        text: el.innerText.trim(),
        isVisible: isElementVisible(el),
        hasLoginKeyword: /log.?in|sign.?in|password|verify/i.test(el.innerText),
      }))
      .filter((link) => link.href.startsWith("http"));
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

    while ((node = walker.nextNode())) {
      const text = node.textContent.trim();
      if (!text) continue;
      chunks.push(text);
    }

    return chunks.join(" ");
  }

  function extractFormInfo() {
    const forms = [];
    document.querySelectorAll("form").forEach(f => {
      let actionHost = "";
      try { actionHost = f.action ? new URL(f.action).hostname : ""; } catch {}
      forms.push({ actionHost, hasPassword: !!f.querySelector('input[type="password"]'),
                   hiddenInputCount: f.querySelectorAll('input[type="hidden"]').length });
    });
    if (!forms.length && document.querySelector('input[type="password"]'))
      forms.push({ actionHost: "", hasPassword: true, hiddenInputCount: 0 });
    return forms;
  }

  function extractIframeInfo() {
    return Array.from(document.querySelectorAll("iframe")).map(f => {
      const s = window.getComputedStyle(f);
      const isHidden = s.display === "none" || s.visibility === "hidden" || s.opacity === "0" || f.offsetWidth === 0;
      let isCrossOrigin = false;
      try { if (f.src) isCrossOrigin = new URL(f.src).hostname !== window.location.hostname; } catch {}
      return { src: f.src || "", isHidden, isCrossOrigin };
    });
  }

  function extractScriptInfo() {
    let inline = 0, jsFuck = false, evalAtob = false, blockRC = false, blockDT = false, miner = false;

    document.querySelectorAll("script").forEach(s => {
      const c = s.textContent || "";
      if (!s.src) inline++;
      if (c.length > 200 && /^[\[\]\+\!\(\)\s]+$/.test(c)) jsFuck = true;
      if (/eval\s*\(\s*atob\s*\(/.test(c)) evalAtob = true;
      if (/addEventListener.*contextmenu.*preventDefault/.test(c)) blockRC = true;
      if (/F12|keydown.*F12|debugger\s*;?\s*\}/.test(c)) blockDT = true;
      if (/coinhive|crypto-loot|coinimp|minexmr/i.test(c + s.src)) miner = true;
    });
    if (!blockRC && document.querySelector('[oncontextmenu]')) blockRC = true;

    return { inlineScriptCount: inline, hasJsFuck: jsFuck, hasEvalAtob: evalAtob,
             blocksRightClick: blockRC, blocksDevTools: blockDT, hasCryptoMiner: miner };
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

// content/scanner.js

const ScamShieldScanner = (() => {
  let localRiskMap = {};
  let lastFingerprint = "";
  let debounceTimer = null;
  let isScanning = false;
  let lastPageResult = null;

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

    if (!window.ScamShieldUI) return;

    if (!result || result.verdict === "safe") {
      window.ScamShieldUI.removeWarningUI();
      return;
    }

    if (result.verdict === "suspicious") {
      window.ScamShieldUI.showSuspiciousBanner({
        score: result.score,
        onOpenPanel: openSidePanel,
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

        const score = localRiskMap[href] ?? 0;
        if (score < 70) return;

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
      chrome.storage.session.set({ linkRiskMap: localRiskMap }).catch(() => {});
    }

    if (message.type === "SCAN_STAGE_HEURISTIC") {
      syncPageWarnings(message.result);
    }

    if (message.type === "SCAN_STAGE_AI") {
      syncPageWarnings(message.result);

      const overlay = document.getElementById("scamshield-danger-overlay");
      const reasonEl = overlay?.querySelector("#ss-danger-reason");
      if (reasonEl && message.result?.explanation?.reason) {
        reasonEl.textContent = message.result.explanation.reason;
      }
    }
  }

  async function restoreSessionState() {
    try {
      const state = await chrome.storage.session.get(["linkRiskMap", "lastPageResult", "lastScan"]);
      const restoredResult = state.lastPageResult || state.lastScan || null;
      const currentUrl = normalizeUrl(window.location.href);

      if (restoredResult?.url === currentUrl) {
        localRiskMap = state.linkRiskMap || {};
        syncPageWarnings(restoredResult);
      }
    } catch (error) {
      console.warn("[ScamShield] Failed to restore session state:", error);
    }
  }

  async function init() {
    await restoreSessionState();
    chrome.runtime.onMessage.addListener(handleRuntimeMessage);
    attachClickInterceptor();
    startMutationWatcher();
    runScan("PAGE_LOADED");
  }

  return { init };
})();

ScamShieldScanner.init();

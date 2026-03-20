const ScamShieldScanner = (() => {
  const OVERLAY_ID = "scamshield-overlay";
  const RISK_THRESHOLD = 70;
  const MAX_VISIBLE_TEXT_LENGTH = 3000;
  const MAX_LINKS = 80;
  let debounceTimer = null;
  let localRiskMap = {};

  function extractPageContext() {
    return {
      url: window.location.href,
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
        href: el.href,
        text: el.innerText.trim().slice(0, 120),
        isVisible: isElementVisible(el),
        hasLoginKeyword: /log.?in|sign.?in|password|verify/i.test(el.innerText),
      }))
      .filter((link) => link.href.startsWith("http"))
      .slice(0, MAX_LINKS);
  }

  function extractVisibleText() {
    if (!document.body) {
      return "";
    }

    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode(node) {
          const parent = node.parentElement;
          if (!parent) return NodeFilter.FILTER_REJECT;
          if (["SCRIPT", "STYLE", "NOSCRIPT"].includes(parent.tagName))
            return NodeFilter.FILTER_REJECT;
          if (!isElementVisible(parent)) return NodeFilter.FILTER_REJECT;
          return node.textContent.trim()
            ? NodeFilter.FILTER_ACCEPT
            : NodeFilter.FILTER_REJECT;
        },
      }
    );

    const chunks = [];
    let totalLength = 0;
    let node;
    while ((node = walker.nextNode()) && totalLength < MAX_VISIBLE_TEXT_LENGTH) {
      const text = node.textContent.trim();
      const remaining = MAX_VISIBLE_TEXT_LENGTH - totalLength;
      const nextChunk = text.slice(0, remaining);
      chunks.push(nextChunk);
      totalLength += nextChunk.length + 1;
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

  function startMutationWatcher() {
    if (!document.body) {
      return;
    }

    const observer = new MutationObserver((mutations) => {
      const meaningful = mutations.some((mutation) => mutation.addedNodes.length > 0);
      if (!meaningful) return;

      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        const context = extractPageContext();
        sendToBackground({ type: "PAGE_UPDATED", context });
      }, 1500);
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  function findAnchorFromEvent(event) {
    const eventTarget = event.target;
    if (eventTarget instanceof Element) {
      return eventTarget.closest("a[href]");
    }

    return null;
  }

  function attachClickInterceptor() {
    document.addEventListener(
      "click",
      (e) => {
        const anchor = findAnchorFromEvent(e);
        if (!anchor) return;

        const href = anchor.href;
        if (!href.startsWith("http")) {
          return;
        }

        const score = localRiskMap[href];
        if (score >= RISK_THRESHOLD) {
          e.preventDefault();
          showWarningOverlay(anchor, href, score);
        }
      },
      true
    );
  }

  function showWarningOverlay(anchor, href, score) {
    document.getElementById(OVERLAY_ID)?.remove();

    const overlay = document.createElement("div");
    overlay.id = OVERLAY_ID;
    overlay.innerHTML = `
      <div style="
        position: fixed; inset: 0; z-index: 2147483647;
        background: rgba(0,0,0,0.75); display: flex;
        align-items: center; justify-content: center;
        font-family: system-ui, sans-serif;
      ">
        <div style="
          background: #1a1a2e; color: white; padding: 32px;
          border-radius: 12px; max-width: 480px; width: 90%;
          border: 2px solid #e63946;
        ">
          <div style="font-size: 2rem; margin-bottom: 8px;">⚠️ Dangerous Link</div>
          <p style="color: #e63946; font-size: 1.1rem; margin: 0 0 12px;">
            Risk Score: ${score}/100
          </p>
          <p style="color: #ccc; word-break: break-all; font-size: 0.85rem;">
            ${href}
          </p>
          <div style="display:flex; gap: 12px; margin-top: 24px;">
            <button id="ss-go-back" style="
              flex:1; padding: 12px; background: #e63946;
              border: none; border-radius: 8px; color: white;
              cursor: pointer; font-size: 1rem;
            ">← Go Back</button>
            <button id="ss-ignore" style="
              flex:1; padding: 12px; background: #444;
              border: none; border-radius: 8px; color: white;
              cursor: pointer; font-size: 1rem;
            ">Proceed Anyway</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("ss-go-back").onclick = () => overlay.remove();
    document.getElementById("ss-ignore").onclick = () => {
      overlay.remove();
      window.location.href = href;
    };
  }

  function sendToBackground(message) {
    chrome.runtime.sendMessage(message).catch(() => {
      // The service worker can wake back up on the next message.
    });
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "RISK_SCORES") {
      localRiskMap = message.riskMap || {};
      chrome.storage.session.set({ riskMap: message.riskMap || {} }).catch(() => {});
    }
  });

  function loadPersistedRiskMap() {
    chrome.storage.session.get(["riskMap"], (result) => {
      localRiskMap = result.riskMap || {};
    });
  }

  function bootstrapWhenReady() {
    if (document.body) {
      init();
      return;
    }

    window.addEventListener(
      "DOMContentLoaded",
      () => {
        init();
      },
      { once: true }
    );
  }

  function init() {
    loadPersistedRiskMap();
    const context = extractPageContext();
    sendToBackground({ type: "PAGE_LOADED", context });
    startMutationWatcher();
    attachClickInterceptor();
  }

  return { init: bootstrapWhenReady };
})();

ScamShieldScanner.init();

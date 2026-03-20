// content/scanner.js

const ScamShieldScanner = (() => {
  let localRiskMap = {};

  // ── 1. PAGE SNAPSHOT ──────────────────────────────────────────────
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
        href: el.href,                          // resolved absolute URL
        text: el.innerText.trim().slice(0, 120),
        isVisible: isElementVisible(el),
        hasLoginKeyword: /log.?in|sign.?in|password|verify/i.test(el.innerText),
      }))
      .filter((l) => l.href.startsWith("http")) // skip mailto:, #anchors, etc.
      .slice(0, 80);                             // cap at 80 links to keep payload lean
  }

  function extractVisibleText() {
    // Walk the body, grab text nodes that are actually rendered
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
    let node;
    while ((node = walker.nextNode()) && chunks.join(" ").length < 3000) {
      chunks.push(node.textContent.trim());
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

  // ── 2. MUTATIONOBSERVER — watch for dynamic content ────────────────
  let debounceTimer = null;

  function startMutationWatcher() {
    const observer = new MutationObserver((mutations) => {
      // Debounce: don't fire on every tiny DOM tweak (e.g. ad rotation)
      const meaningful = mutations.some(
        (m) => m.addedNodes.length > 0 || m.type === "childList"
      );
      if (!meaningful) return;

      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        const context = extractPageContext();
        sendToBackground({ type: "PAGE_UPDATED", context });
      }, 1500); // wait 1.5s after last mutation before re-scanning
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  // ── 3. CLICK INTERCEPTION — pause before risky navigation ─────────
  function attachClickInterceptor() {
    document.addEventListener(
      "click",
      (e) => {
        const anchor = e.target.closest("a[href]");
        if (!anchor) return;

        const href = anchor.href;
        if (!href.startsWith("http")) return;

        // Check the local risk map synchronously
        const score = localRiskMap[href];
        if (score >= 70) {
          e.preventDefault();
          e.stopPropagation(); // Stop other click handlers
          showWarningOverlay(anchor, href, score);
        }
      },
      true // capture phase — fires before the page's own handlers
    );
  }

  // ── 4. WARNING OVERLAY ────────────────────────────────────────────
  function showWarningOverlay(anchor, href, score) {
    // Remove any existing overlay
    document.getElementById("scamshield-overlay")?.remove();

    const overlay = document.createElement("div");
    overlay.id = "scamshield-overlay";
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

  // ── 5. MESSAGE BUS ────────────────────────────────────────────────
  function sendToBackground(message) {
    chrome.runtime.sendMessage(message).catch(() => {
      // Background service worker may have gone idle — that's fine
    });
  }

  // Listen for risk scores coming back from the background
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "RISK_SCORES") {
      // Update our local synchronous map
      localRiskMap = Object.assign(localRiskMap, message.riskMap);
      // Also save to session storage for other components if needed
      chrome.storage.session.set({ riskMap: localRiskMap });
    }
  });

  // ── 6. INIT ───────────────────────────────────────────────────────
  function init() {
    const context = extractPageContext();
    sendToBackground({ type: "PAGE_LOADED", context });
    startMutationWatcher();
    attachClickInterceptor();
  }

  return { init };
})();

ScamShieldScanner.init();

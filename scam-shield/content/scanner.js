// content/scanner.js

const ScamShieldScanner = (() => {
  let localRiskMap = {};
  let activeLinkUrl = null;
  let pageWarningDismissed = false;

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
      .slice(0, 80);
  }

  function extractVisibleText() {
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

  let debounceTimer = null;

  function startMutationWatcher() {
    const observer = new MutationObserver((mutations) => {
      const meaningful = mutations.some(
        (mutation) => mutation.addedNodes.length > 0 || mutation.type === "childList"
      );
      if (!meaningful) return;

      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        sendToBackground({ type: "PAGE_UPDATED", context: extractPageContext() });
      }, 1500);
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  function attachClickInterceptor() {
    document.addEventListener(
      "click",
      (event) => {
        const openPanelButton = event.target.closest("#ss-open-panel");
        if (openPanelButton) {
          event.preventDefault();
          event.stopPropagation();
          chrome.runtime.sendMessage({ type: "OPEN_SIDE_PANEL" });
          return;
        }

        const anchor = event.target.closest("a[href]");
        if (!anchor) return;

        const href = anchor.href;
        if (!href.startsWith("http")) return;

        const score = localRiskMap[href];
        if (score >= 70) {
          event.preventDefault();
          event.stopPropagation();
          activeLinkUrl = href;
          renderLinkOverlay(buildPendingLinkAnalysis(href, score));
          sendToBackground({
            type: "ANALYZE_LINK",
            link: {
              href,
              text: anchor.innerText.trim().slice(0, 120),
            },
            pageContext: {
              url: window.location.href,
              title: document.title,
              visibleText: extractVisibleText().slice(0, 800),
            },
          });
        }
      },
      true
    );
  }

  function buildPendingLinkAnalysis(url, score) {
    return {
      subjectType: "link",
      url,
      score,
      verdict: score >= 70 ? "dangerous" : "suspicious",
      scamType: "Analyzing suspicious link",
      signals: [],
      aiStatus: "pending",
      headline: "Analyzing blocked link",
      reason: "Checking the destination and URL for scam indicators now.",
      riskLocation: "The suspicious part is likely in the destination URL or login flow.",
      preventionTips: [
        "Pause before opening unfamiliar links that ask you to sign in.",
        "Verify the real website domain before entering any details.",
      ],
      recommendedAction: "Wait for the analysis before deciding whether to proceed.",
      destinationSummary: null,
    };
  }

  function renderLinkOverlay(analysis) {
    document.getElementById("scamshield-link-overlay")?.remove();

    const overlay = document.createElement("div");
    overlay.id = "scamshield-link-overlay";
    overlay.innerHTML = `
      <div style="
        position: fixed; inset: 0; z-index: 2147483647;
        background: rgba(8,10,18,0.84); display: flex;
        align-items: center; justify-content: center;
        font-family: system-ui, sans-serif; padding: 24px;
      ">
        <div style="
          background: #1a1a2e; color: white; padding: 28px;
          border-radius: 18px; max-width: 720px; width: 100%;
          border: 2px solid #e63946; box-shadow: 0 24px 64px rgba(0,0,0,0.45);
        ">
          ${buildAnalysisMarkup(analysis, { compact: false, includePanelButton: false })}
          <div style="display:flex; gap: 12px; margin-top: 24px;">
            <button id="ss-go-back" style="
              flex:1; padding: 12px; background: #e63946;
              border: none; border-radius: 10px; color: white;
              cursor: pointer; font-size: 1rem;
            ">Take Me Back</button>
            <button id="ss-ignore" style="
              flex:1; padding: 12px; background: #444;
              border: none; border-radius: 10px; color: white;
              cursor: pointer; font-size: 1rem;
            ">I understand the risks, proceed anyway</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("ss-go-back").onclick = handleGoBack;
    document.getElementById("ss-ignore").onclick = () => {
      overlay.remove();
      window.location.href = analysis.url;
    };
  }

  function renderPageWarning(analysis) {
    const existing = document.getElementById("scamshield-page-warning");

    if (analysis.score < 30) {
      document.body.style.overflow = "auto";
      existing?.remove();
      return;
    }

    if (analysis.score >= 70 && pageWarningDismissed) {
      return;
    }

    const root = existing || document.createElement("div");
    root.id = "scamshield-page-warning";

    if (analysis.score >= 70) {
      document.body.style.overflow = "hidden";
      root.innerHTML = `
        <div style="
          position: fixed; inset: 0; z-index: 2147483647;
          background: #0f0f13; display: flex; align-items: center;
          justify-content: center; padding: 24px; font-family: system-ui, sans-serif;
        ">
          <div style="
            width: min(760px, 100%); background: #181826; color: white;
            border: 2px solid #e63946; border-radius: 20px; padding: 28px;
            box-shadow: 0 28px 80px rgba(0,0,0,0.5);
          ">
            ${buildAnalysisMarkup(analysis, { compact: false, includePanelButton: false })}
            <div style="display:flex; gap: 12px; margin-top: 24px;">
              <button id="ss-page-go-back" style="
                flex:1; padding: 12px; background: #e63946;
                border: none; border-radius: 10px; color: white; cursor: pointer;
                font-size: 1rem;
              ">Take Me Back</button>
              <button id="ss-page-proceed" style="
                flex:1; padding: 12px; background: #444;
                border: none; border-radius: 10px; color: white; cursor: pointer;
                font-size: 1rem;
              ">I understand the risks, proceed anyway</button>
            </div>
          </div>
        </div>
      `;
    } else {
      document.body.style.overflow = "auto";
      root.innerHTML = `
        <div style="
          position: fixed; top: 18px; right: 18px; z-index: 2147483646;
          width: min(420px, calc(100vw - 36px)); background: #fff4df; color: #2b1a0f;
          border: 1px solid #f4b860; border-radius: 18px; padding: 18px 18px 16px;
          box-shadow: 0 18px 48px rgba(0,0,0,0.18); font-family: system-ui, sans-serif;
        ">
          ${buildAnalysisMarkup(analysis, { compact: true, includePanelButton: true })}
        </div>
      `;
    }

    if (!existing) {
      document.body.appendChild(root);
    }

    const pageBackButton = document.getElementById("ss-page-go-back");
    if (pageBackButton) {
      pageBackButton.onclick = handleGoBack;
    }

    const pageProceedButton = document.getElementById("ss-page-proceed");
    if (pageProceedButton) {
      pageProceedButton.onclick = () => {
        pageWarningDismissed = true;
        document.body.style.overflow = "auto";
        root.remove();
      };
    }

    const panelButton = document.getElementById("ss-open-panel");
    if (panelButton) {
      panelButton.onclick = () => {
        chrome.runtime.sendMessage({ type: "OPEN_SIDE_PANEL" });
      };
    }
  }

  function buildAnalysisMarkup(analysis, { compact, includePanelButton }) {
    const toneColor =
      analysis.verdict === "dangerous" ? "#ff4d5b" : analysis.verdict === "suspicious" ? "#b56c00" : "#1f8f4d";
    const signalItems = analysis.signals.length
      ? analysis.signals
          .map(
            (signal) =>
              `<li style="margin-bottom: 6px;">${escapeHtml(signal.reason)}</li>`
          )
          .join("")
      : `<li>No strong heuristic indicators were available yet.</li>`;
    const preventionItems = (analysis.preventionTips || [])
      .map((tip) => `<li style="margin-bottom: 6px;">${escapeHtml(tip)}</li>`)
      .join("");
    const loadingMessage =
      analysis.aiStatus === "pending"
        ? `<p style="margin: 0 0 14px; color: ${compact ? "#6a4b1c" : "#d7d7df"};">Analyzing the content for a clearer explanation...</p>`
        : analysis.aiStatus === "unavailable"
          ? `<p style="margin: 0 0 14px; color: ${compact ? "#6a4b1c" : "#d7d7df"};">AI explanation unavailable, showing the fastest heuristic explanation instead.</p>`
          : "";

    return `
      <div style="display:flex; align-items:center; gap: 12px; margin-bottom: 12px;">
        <div style="font-size:${compact ? "1.8rem" : "2.4rem"};">${analysis.verdict === "dangerous" ? "⚠️" : "⚠"}</div>
        <div>
          <div style="font-size:${compact ? "1.3rem" : "1.9rem"}; font-weight: 700;">${escapeHtml(analysis.headline)}</div>
          <div style="color:${toneColor}; font-size:${compact ? "0.98rem" : "1.05rem"}; font-weight: 600;">
            ${escapeHtml(analysis.verdict.toUpperCase())} • Risk Score: ${analysis.score}/100
          </div>
        </div>
      </div>
      <p style="margin: 0 0 10px; font-size:${compact ? "0.95rem" : "1rem"}; color:${compact ? "#5e4121" : "#cfcfda"};">
        ${escapeHtml(analysis.url)}
      </p>
      ${loadingMessage}
      <div style="display:grid; gap: ${compact ? "12px" : "16px"};">
        <section>
          <div style="font-size:0.82rem; letter-spacing:0.06em; text-transform:uppercase; opacity:0.7; margin-bottom: 6px;">Likely Scam Type</div>
          <div style="font-size:${compact ? "1rem" : "1.08rem"}; font-weight: 600;">${escapeHtml(analysis.scamType)}</div>
        </section>
        <section>
          <div style="font-size:0.82rem; letter-spacing:0.06em; text-transform:uppercase; opacity:0.7; margin-bottom: 6px;">Why This Was Flagged</div>
          <p style="margin: 0; line-height: 1.5;">${escapeHtml(analysis.reason)}</p>
        </section>
        <section>
          <div style="font-size:0.82rem; letter-spacing:0.06em; text-transform:uppercase; opacity:0.7; margin-bottom: 6px;">Most Notable Signals</div>
          <ul style="margin: 0; padding-left: 18px; line-height: 1.4;">${signalItems}</ul>
        </section>
        <section>
          <div style="font-size:0.82rem; letter-spacing:0.06em; text-transform:uppercase; opacity:0.7; margin-bottom: 6px;">Where The Scam Likely Is</div>
          <p style="margin: 0; line-height: 1.5;">${escapeHtml(analysis.riskLocation)}</p>
        </section>
        ${
          analysis.destinationSummary?.snippet
            ? `<section>
                <div style="font-size:0.82rem; letter-spacing:0.06em; text-transform:uppercase; opacity:0.7; margin-bottom: 6px;">Destination Preview</div>
                <p style="margin: 0; line-height: 1.5;">${escapeHtml(analysis.destinationSummary.snippet.slice(0, compact ? 180 : 320))}</p>
              </section>`
            : ""
        }
        <section>
          <div style="font-size:0.82rem; letter-spacing:0.06em; text-transform:uppercase; opacity:0.7; margin-bottom: 6px;">How To Avoid Scams Like This</div>
          <ul style="margin: 0; padding-left: 18px; line-height: 1.4;">${preventionItems}</ul>
        </section>
        <section>
          <div style="font-size:0.82rem; letter-spacing:0.06em; text-transform:uppercase; opacity:0.7; margin-bottom: 6px;">What To Do Right Now</div>
          <p style="margin: 0; line-height: 1.5;">${escapeHtml(analysis.recommendedAction)}</p>
        </section>
      </div>
      ${
        includePanelButton
          ? `<button id="ss-open-panel" style="
              margin-top: 16px; width: 100%; padding: 11px 12px;
              border: none; border-radius: 12px; background: #2c2f7f;
              color: white; cursor: pointer; font-size: 0.96rem; font-weight: 600;
            ">Open in Side Panel</button>`
          : ""
      }
    `;
  }

  function handleGoBack() {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
      setTimeout(() => {
        window.location.href = "chrome://newtab";
      }, 300);
    }
  }

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function sendToBackground(message) {
    try {
      chrome.runtime.sendMessage(message).catch(() => {});
    } catch (err) {
      if (err && err.message && !err.message.includes("Extension context invalidated")) {
        console.warn("[ScamShield] Send error:", err);
      }
    }
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "RISK_SCORES") {
      localRiskMap = Object.assign(localRiskMap, message.riskMap);
      chrome.storage.session.set({ riskMap: localRiskMap });
    }

    if (message.type === "PAGE_SCAN_RESULT" || message.type === "PAGE_EXPLANATION") {
      renderPageWarning(message.analysis);
      chrome.storage.session.set({ pageAnalysis: message.analysis });
    }

    if (message.type === "LINK_ANALYSIS_RESULT" && message.analysis?.url === activeLinkUrl) {
      renderLinkOverlay(message.analysis);
    }
  });

  function init() {
    sendToBackground({ type: "PAGE_LOADED", context: extractPageContext() });
    startMutationWatcher();
    attachClickInterceptor();
  }

  return { init };
})();

ScamShieldScanner.init();

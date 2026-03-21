// content/scanner.js

const ScamShieldScanner = (() => {
  let elementRiskMap = {}; // elementId -> risk data
  
  // Generate a unique ID for this frame to avoid collisions across iframes
  const FRAME_ID = Math.random().toString(36).substring(2, 10);

  // Extract XPath from elementId (format: frameId:xpath:tag)
  function getXPathFromElementId(elementId) {
    const first = elementId.indexOf(":");
    const last = elementId.lastIndexOf(":");
    if (first === -1 || last === -1 || first === last) return elementId;
    return elementId.substring(first + 1, last);
  }

  // ── 1. ELEMENT EXTRACTION ──────────────────────────────────────────
  function generateElementId(el) {
    // Generate a stable ID using XPath + frame ID
    return FRAME_ID + ":" + getXPath(el) + ":" + el.tagName.toLowerCase();
  }

  function getXPath(element) {
    if (element.id) return `//*[@id="${element.id}"]`;
    if (element === document.body) return "/html/body";
    
    const siblings = Array.from(element.parentNode.children);
    const index = siblings.indexOf(element) + 1;
    const parentXPath = getXPath(element.parentNode);
    return `${parentXPath}/${element.tagName.toLowerCase()}[${index}]`;
  }

  function extractPageContext() {
    return {
      url: window.location.href,
      title: document.title,
      visibleText: extractVisibleText(),
      timestamp: Date.now(),
      elements: extractAllElements()
    };
  }

  function extractAllElements() {
    const elements = [];
    
    // Links
    document.querySelectorAll("a[href]").forEach(el => {
      const href = el.href;
      if (href.startsWith("http")) {
        elements.push({
          elementId: generateElementId(el),
          type: "link",
          url: href,
          text: el.innerText.trim().slice(0, 120),
          isVisible: isElementVisible(el),
          hasLoginKeyword: /log.?in|sign.?in|password|verify|account/i.test(el.innerText)
        });
      }
    });
    
    // Buttons (with onclick or type=submit)
    document.querySelectorAll("button").forEach(el => {
      const hasOnclick = el.hasAttribute("onclick");
      const formSubmit = el.type === "submit";
      if (hasOnclick || formSubmit || el.closest("form")) {
        elements.push({
          elementId: generateElementId(el),
          type: "button",
          text: el.innerText.trim().slice(0, 80) || el.getAttribute("aria-label") || "",
          hasOnclick,
          formSubmit,
          isVisible: isElementVisible(el)
        });
      }
    });
    
    // File inputs
    document.querySelectorAll('input[type="file"]').forEach(el => {
      elements.push({
        elementId: generateElementId(el),
        type: "fileInput",
        text: el.getAttribute("accept") || "File upload",
        isVisible: isElementVisible(el)
      });
    });
    
    // Download links (<a download>)
    document.querySelectorAll("a[download]").forEach(el => {
      const href = el.href;
      if (href && href.startsWith("http")) {
        elements.push({
          elementId: generateElementId(el),
          type: "download",
          url: href,
          text: el.innerText.trim().slice(0, 80) || el.getAttribute("download"),
          isVisible: isElementVisible(el)
        });
      }
    });
    
    // iframes
    document.querySelectorAll("iframe[src]").forEach(el => {
      const src = el.src;
      if (src.startsWith("http")) {
        elements.push({
          elementId: generateElementId(el),
          type: "iframe",
          url: src,
          isVisible: isElementVisible(el)
        });
      }
    });
    
    // Media elements (video, audio, embed, object)
    document.querySelectorAll("video[src], audio[src], embed[src], object[data]").forEach(el => {
      const src = el.src || el.getAttribute("data");
      if (src && src.startsWith("http")) {
        elements.push({
          elementId: generateElementId(el),
          type: el.tagName.toLowerCase(),
          url: src,
          isVisible: isElementVisible(el)
        });
      }
    });
    
    // Forms
    document.querySelectorAll("form").forEach(el => {
      const action = el.action;
      if (action && action.startsWith("http")) {
        elements.push({
          elementId: generateElementId(el),
          type: "form",
          url: action,
          method: el.method,
          isVisible: isElementVisible(el)
        });
      }
    });
    
    // Input type=submit and type=image
    document.querySelectorAll('input[type="submit"], input[type="image"]').forEach(el => {
      elements.push({
        elementId: generateElementId(el),
        type: "button",
        text: el.value || el.getAttribute('aria-label') || '',
        hasOnclick: el.hasAttribute('onclick'),
        formSubmit: true,
        isVisible: isElementVisible(el)
      });
    });
    
    // Generic clickable elements with onclick (not already captured)
    document.querySelectorAll('[onclick]').forEach(el => {
      // Skip if already captured as a button, input, link, or form
      if (el.closest('button, input, a, form')) return;
      elements.push({
        elementId: generateElementId(el),
        type: "clickable",
        text: el.innerText.trim().slice(0, 80) || el.getAttribute('aria-label') || '',
        hasOnclick: true,
        isVisible: isElementVisible(el)
      });
    });
    
    return elements;
  }

  function extractVisibleText() {
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
    if (!el || !el.offsetParent) return false;
    const style = window.getComputedStyle(el);
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      style.opacity !== "0" &&
      el.offsetWidth > 0 &&
      el.offsetHeight > 0
    );
  }

  // ── 2. MUTATION OBSERVER ───────────────────────────────────────────
  let debounceTimer = null;

  function startMutationWatcher() {
    const observer = new MutationObserver((mutations) => {
      const meaningful = mutations.some(
        (m) => m.addedNodes.length > 0 || m.type === "childList"
      );
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

  // ── 3. CHAT BUBBLE UI ──────────────────────────────────────────────
  function showOrUpdateBubble(elementId, data) {
    // If safe, remove any bubble and restore element
    if (data.status === "safe") {
      document.getElementById(`ss-bubble-${elementId}`)?.remove();
      restoreElement(elementId);
      return;
    }
    
    // If dangerous, disable element first
    if (data.riskScore >= 70) {
      disableElement(elementId, data);
    }
    
    let bubble = document.getElementById(`ss-bubble-${elementId}`);
    
    if (!bubble) {
      bubble = document.createElement("div");
      bubble.id = `ss-bubble-${elementId}`;
      bubble.style.cssText = `
        position: absolute;
        z-index: 2147483647;
        background: #1a1a2e;
        border: 2px solid ${data.riskScore >= 70 ? '#e63946' : '#ffc107'};
        border-radius: 8px;
        padding: 12px;
        max-width: 320px;
        color: white;
        font-family: system-ui, sans-serif;
        font-size: 14px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.5);
        pointer-events: auto;
      `;
      document.body.appendChild(bubble);
    }
    
    // Set content with short explanation, hidden long explanation, and visit anyway link
    bubble.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
        <strong style="color: ${data.riskScore >= 70 ? '#e63946' : '#ffc107'};">
          ⚠️ Risk: ${data.riskScore}/100
        </strong>
        <button onclick="document.getElementById('ss-bubble-${elementId}').remove()" 
                style="background:none;border:none;color:white;cursor:pointer;margin-left:8px;font-size:1.2em;">✕</button>
      </div>
      <p style="margin: 0 0 10px 0; color: #ccc; line-height: 1.4; font-size: 0.95em;">
        ${data.shortExplanation || "This element is dangerous. Proceed with extreme caution."}
      </p>
      <div id="ss-long-${elementId}" style="display:none; margin: 0 0 10px 0; padding: 8px; border-top: 1px solid #444; color: #aaa; font-size: 0.85em; line-height: 1.4;">
        ${data.longExplanation || "Loading detailed analysis..."}
      </div>
      <div style="display:flex; gap:8px; align-items:center;">
        <a href="#" id="ss-visit-${elementId}" target="_blank" style="
          flex:1; padding:6px 12px; background:${data.riskScore >= 70 ? '#e63946' : '#ffc107'};
          border:none; border-radius:4px; color:white; text-align:center;
          text-decoration:none; font-size:0.9em; cursor:pointer;
        ">Visit Anyway</a>
        <a href="#" id="ss-explain-${elementId}" style="
          padding:6px 12px; background:transparent; border:1px solid #4dabf7;
          border-radius:4px; color:#4dabf7; text-decoration:none; font-size:0.9em;
          cursor:pointer;
        ">Explain more</a>
      </div>
    `;

    // Position bubble near the target element
    positionBubbleNearElement(elementId, bubble);

    // Handle "Visit Anyway" click
    const visitLink = bubble.querySelector(`#ss-visit-${elementId}`);
    if (visitLink) {
      visitLink.onclick = (e) => {
        e.preventDefault();
        // Restore element temporarily and navigate
        if (restoreElement(elementId)) {
          if (data.url) window.open(data.url, '_blank');
          bubble.remove();
        } else {
          // Fallback: direct navigation
          if (data.url) window.open(data.url, '_blank');
        }
      };
    }

    // Handle "Explain more" toggle — expand inline, no modal
    const explainLink = bubble.querySelector(`#ss-explain-${elementId}`);
    if (explainLink) {
      explainLink.onclick = (e) => {
        e.preventDefault();
        const longDiv = bubble.querySelector(`#ss-long-${elementId}`);
        if (longDiv) {
          const isHidden = longDiv.style.display === "none";
          longDiv.style.display = isHidden ? "block" : "none";
          explainLink.textContent = isHidden ? "Show less" : "Explain more";
        }
      };
    }
  }

  function positionBubbleNearElement(elementId, bubble) {
    const xpath = getXPathFromElementId(elementId);
    const el = evaluateXPath(xpath);
    
    if (el) {
      const rect = el.getBoundingClientRect();
      // position:absolute relative to document, not viewport — add scroll offset
      bubble.style.top = `${rect.bottom + window.scrollY + 5}px`;
      bubble.style.left = `${rect.left + window.scrollX}px`;
    } else {
      bubble.style.top = `${window.scrollY + 100}px`;
      bubble.style.right = "20px";
    }
  }

  function evaluateXPath(path) {
    return document.evaluate(
      path,
      document,
      null,
      XPathResult.FIRST_ORDERED_NODE_TYPE,
      null
    ).singleNodeValue;
  }

  // ── 4. CLICK INTERCEPTION ──────────────────────────────────────────
  function attachClickInterceptor() {
    document.addEventListener(
      "click",
      (e) => {
        const target = e.target.closest("a[href], button, [onclick], [data-ss-original-href], input[type=submit], input[type=image]");
        if (!target) return;
        
        const elementId = generateElementId(target);
        const riskData = elementRiskMap[elementId];
        
        if (riskData && riskData.status === "unsafe" && riskData.riskScore >= 70) {
          e.preventDefault();
          e.stopImmediatePropagation();
          
          // Show bubble
          showOrUpdateBubble(elementId, riskData);
        }
      },
      true
    );
  }

  // ── 5. ELEMENT DISABLE & REPLACEMENT ───────────────────────────────
  function disableElement(elementId, data) {
    const xpath = getXPathFromElementId(elementId);
    const el = evaluateXPath(xpath);
    if (!el) return;
    
    if (el.dataset.ssDisabled === "true") return; // already disabled
    
    const tag = el.tagName.toLowerCase();
    const originalUrl = data.url || el.href || el.src || el.action;
    
    // Save original state in dataset
    if (tag === 'a' && el.href) {
      el.dataset.ssOriginalHref = el.href;
      el.dataset.ssOriginalTarget = el.target;
      el.dataset.ssOriginalRel = el.rel;
      el.removeAttribute('href');
      el.style.cursor = 'not-allowed';
      el.style.color = '#999';
      el.style.textDecoration = 'line-through';
    } else if ((tag === 'button' || el.hasAttribute('onclick')) && !el.disabled) {
      el.dataset.ssOriginalOnclick = el.getAttribute('onclick') || '';
      el.removeAttribute('onclick');
      if (tag === 'button') {
        el.disabled = true;
        el.style.opacity = '0.5';
        el.style.cursor = 'not-allowed';
      }
    } else if (tag === 'input' && el.type === 'file') {
      el.disabled = true;
      el.dataset.ssOriginalAccept = el.accept || '';
      // Hide original and add warning
      const warning = document.createElement('span');
      warning.textContent = 'File upload blocked (dangerous)';
      warning.style.color = '#e63946';
      warning.style.fontSize = '0.9em';
      el.parentNode.insertBefore(warning, el);
      el.dataset.ssPlaceholder = 'true';
    } else if (['iframe', 'video', 'audio', 'embed', 'object'].includes(tag)) {
      const src = el.src || el.getAttribute('data');
      if (src) el.dataset.ssOriginalSrc = src;
      el.style.display = 'none';
      const warning = document.createElement('div');
      warning.textContent = 'Embedded content blocked (dangerous)';
      warning.style.color = '#e63946';
      warning.style.fontSize = '0.9em';
      warning.style.padding = '4px 0';
      el.parentNode.insertBefore(warning, el);
      el.dataset.ssPlaceholder = 'true';
    } else if (tag === 'form' && el.action) {
      el.dataset.ssOriginalAction = el.action;
      el.onsubmit = (e) => {
        e.preventDefault();
        showOrUpdateBubble(elementId, data);
        return false;
      };
      const submitBtn = el.querySelector('button[type="submit"], input[type="submit"]');
      if (submitBtn) {
        submitBtn.dataset.ssOriginalOnclick = submitBtn.getAttribute('onclick') || '';
        submitBtn.disabled = true;
        submitBtn.style.opacity = '0.5';
      }
    }
    
    // Attach click handler to show bubble
    el.addEventListener('click', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      showOrUpdateBubble(elementId, data);
    });
    
    el.dataset.ssDisabled = "true";
  }

  function restoreElement(elementId) {
    const xpath = getXPathFromElementId(elementId);
    const el = evaluateXPath(xpath);
    if (!el) return false;
    
    if (el.dataset.ssDisabled !== "true") return false;
    
    const tag = el.tagName.toLowerCase();
    
    if (tag === 'a') {
      if (el.dataset.ssOriginalHref) {
        el.setAttribute('href', el.dataset.ssOriginalHref);
        if (el.dataset.ssOriginalTarget) el.target = el.dataset.ssOriginalTarget;
        if (el.dataset.ssOriginalRel) el.rel = el.dataset.ssOriginalRel;
      }
      el.style.cssText = el.style.cssText.replace(/cursor:\s*not-allowed;?/g, '');
      el.style.color = '';
      el.style.textDecoration = '';
    } else if (tag === 'button' || el.hasAttribute('onclick')) {
      if (el.dataset.ssOriginalOnclick) {
        el.setAttribute('onclick', el.dataset.ssOriginalOnclick);
      }
      if (tag === 'button' && el.disabled) {
        el.disabled = false;
        el.style.opacity = '1';
        el.style.cursor = '';
      }
    } else if (tag === 'input' && el.type === 'file') {
      el.disabled = false;
      if (el.dataset.ssPlaceholder) {
        const placeholder = el.previousSibling;
        if (placeholder && placeholder.textContent.includes('blocked')) {
          placeholder.remove();
        }
      }
    } else if (['iframe', 'video', 'audio', 'embed', 'object'].includes(tag)) {
      if (el.dataset.ssOriginalSrc) {
        if (['iframe','video','audio'].includes(tag)) el.src = el.dataset.ssOriginalSrc;
        else el.setAttribute('data', el.dataset.ssOriginalSrc);
      }
      el.style.display = '';
      if (el.dataset.ssPlaceholder) {
        const placeholder = el.previousSibling;
        if (placeholder && placeholder.textContent.includes('blocked')) {
          placeholder.remove();
        }
      }
    } else if (tag === 'form') {
      if (el.dataset.ssOriginalAction) el.action = el.dataset.ssOriginalAction;
      const submitBtn = el.querySelector('button[type="submit"], input[type="submit"]');
      if (submitBtn && submitBtn.dataset.ssOriginalOnclick) {
        submitBtn.setAttribute('onclick', submitBtn.dataset.ssOriginalOnclick);
        submitBtn.disabled = false;
        submitBtn.style.opacity = '1';
      }
    }
    
    delete el.dataset.ssDisabled;
    return true;
  }

  // ── 6. MESSAGE BUS ────────────────────────────────────────────────
  function sendToBackground(message) {
    chrome.runtime.sendMessage(message).catch(() => {});
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "ELEMENT_UPDATE") {
      const { elementId, data } = message;
      elementRiskMap[elementId] = data;
      
      // Update bubble if exists
      if (data.status === "unsafe") {
        showOrUpdateBubble(elementId, data);
      } else {
        document.getElementById(`ss-bubble-${elementId}`)?.remove();
      }
    } else if (message.type === "RESTORE_ELEMENT") {
      // From dashboard: restore element then open URL
      const success = restoreElement(message.elementId);
      if (success) {
        const data = elementRiskMap[message.elementId];
        if (data?.url) {
          // Let dashboard open the URL separately
          console.log("[ScamShield] Restored element:", message.elementId);
        }
      }
    }
  });

  function repositionBubble(elementId) {
    const bubble = document.getElementById(`ss-bubble-${elementId}`);
    if (!bubble) return;
    positionBubbleNearElement(elementId, bubble);
  }

  function repositionAllBubbles() {
    Object.keys(elementRiskMap).forEach(elementId => {
      const data = elementRiskMap[elementId];
      if (data.status === 'unsafe') {
        repositionBubble(elementId);
      }
    });
  }

  // Keep bubbles positioned on scroll/resize — uses rAnimationFrame for frame-synced tracking
  let rafId;
  function onScrollOrResize() {
    cancelAnimationFrame(rafId);
    rafId = requestAnimationFrame(repositionAllBubbles);
  }
  window.addEventListener('scroll', onScrollOrResize, { capture: true, passive: true });
  window.addEventListener('resize', onScrollOrResize);

  // Clean up bubbles when their element is removed
  const cleanupObserver = new MutationObserver((mutations) => {
    mutations.forEach(mutation => {
      mutation.removedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          // Check if any bubble's element was removed
          Object.keys(elementRiskMap).forEach(elementId => {
            const xpath = getXPathFromElementId(elementId);
            const exists = evaluateXPath(xpath);
            if (!exists) {
              document.getElementById(`ss-bubble-${elementId}`)?.remove();
            }
          });
        }
      });
    });
  });
  cleanupObserver.observe(document.body, { childList: true, subtree: true });

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

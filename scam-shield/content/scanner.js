// content/scanner.js — optimized: event-driven, deduplicated, single observer

const ScamShieldScanner = (() => {
  const FRAME_ID = Math.random().toString(36).substring(2, 10);
  const SELECTOR = "a[href], form[action], iframe[src], video[src], audio[src], embed[src], object[data], input[type=file]";
  const processedNodes = new WeakSet();
  const scannedHashes = new Set(); // content-hash dedup: scan each unique text only once
  const activeBubbleIds = new Set(); // only reposition bubbles that exist
  let elementRiskMap = {};
  let debounceTimer = null;

  // ── TEXT DETECTION PATTERNS ─────────────────────────────────────────
  const CRYPTO_RE = { ethereum: /\b(0x[a-fA-F0-9]{40})\b/g, bitcoinBech32: /\b(bc1[ac-hj-np-z02-9]{11,71})\b/gi, bitcoinLegacy: /\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g, solana: /\b([1-9A-HJ-NP-Za-km-z]{32,44})\b/g, tron: /\b(T[A-Za-z1-9]{33})\b/g, litecoin: /\b([LM3][a-km-zA-HJ-NP-Z1-9]{26,33})\b/g, xrp: /\b(r[1-9A-HJ-NP-Za-km-z]{25,34})\b/g };
  const SCAM_PATTERNS = [
    { re: /\burgent(?:ly)?\b|\bimmediate(?:ly)?\b|\bact\s+now\b|\bexpires?\s+(?:today|soon|in)\b|\blimited\s+time\b|\bhurry\b|\blast\s+chance\b/gi, cat: 'urgency' },
    { re: /\b(?:account|wallet|access)\s+(?:has\s+been\s+)?(?:compromised|suspended|locked|restricted|disabled|blocked|frozen)\b|\bunauthorized\s+(?:access|activity|login|transaction)\b|\bsuspicious\s+(?:activity|login|transaction|sign[\s-]?in)\b|\bsecurity\s+(?:alert|warning|notice|breach|incident)\b|\bfraud(?:ulent)?\s+(?:activity|alert|detected)\b/gi, cat: 'accountThreat' },
    { re: /\byou(?:'ve|have)\s+won\b|\bcongratulations\b|\bfree\s+(?:crypto|bitcoin|eth|tokens?|nft)\b|\bgiveaway\b|\bclaim\s+your\s+(?:prize|reward|tokens?|airdrop)\b|\bsend\s+\d+\s*(?:btc|eth|sol)\s+to\s+receive\b|\bdouble\s+your\s+(?:crypto|bitcoin|eth)\b/gi, cat: 'giveaway' },
    { re: /\benter\s+your\s+(?:seed\s+phrase|private\s+key|password|mnemonic)\b|\bprovide\s+your\s+(?:seed\s+phrase|private\s+key|recovery\s+phrase)\b|\bseed\s+phrase\s+(?:required|needed|verification)\b|\bconnect\s+your\s+wallet\s+to\s+(?:claim|verify|receive)\b/gi, cat: 'credentialHarvest' },
    { re: /\bverify\s+your\s+(?:account|identity|wallet|email)\b|\bupdate\s+your\s+(?:account|payment|security|information)\b|\byour\s+\w+\s+(?:has\s+been|was)\s+(?:compromised|hacked|breached)\b/gi, cat: 'phishing' },
    { re: /\bwhitelist(?:ed|ing)?\b.*\b(?:address|wallet)\b|\bdrain(?:ed|ing)?\s+(?:wallet|funds)\b|\bhoneypot\b|\brug[\s-]?pull\b|\bapproval\s+(?:required|needed|pending)\b/gi, cat: 'cryptoScam' },
    { re: /\b(?:official|legitimate)\s+(?:support|team|representative)\b|\bwe(?:'ve|have)\s+been\s+trying\s+to\s+reach\b|\bremote\s+(?:access|desk|support)\b|\bcall\s+(?:this|the)\s+number\b/gi, cat: 'socialEng' },
  ];
  const SENSITIVE_KW = ['seed', 'mnemonic', 'private', 'recovery', 'secret', 'passphrase'];
  const RE_SCAN_TAGS = new Set(['SCRIPT','STYLE','NOSCRIPT','META','LINK','HEAD']);

  // ── HELPERS ─────────────────────────────────────────────────────────
  const hasValidUrl = v => v && (v.startsWith("http") || v.startsWith("file:") || v.startsWith("blob:") || v.startsWith("data:"));
  const getXPath = el => { if (el.id) return `//*[@id="${el.id}"]`; if (el === document.body) return "/html/body"; const s = Array.from(el.parentNode.children), i = s.indexOf(el)+1; return `${getXPath(el.parentNode)}/${el.tagName.toLowerCase()}[${i}]`; };
  const getXPathFromId = id => { const f = id.indexOf(":"), l = id.lastIndexOf(":"); return (f===-1||l===-1||f===l) ? id : id.substring(f+1,l); };
  const generateElementId = el => FRAME_ID + ":" + getXPath(el) + ":" + el.tagName.toLowerCase();
  const evaluateXPath = p => document.evaluate(p, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
  const isElementVisible = el => { if (!el?.offsetParent) return false; const s = getComputedStyle(el); return s.display!=="none" && s.visibility!=="hidden" && s.opacity!=="0" && el.offsetWidth>0 && el.offsetHeight>0; };
  const escapeHtml = s => { const e = document.createElement('span'); e.textContent = s; return e.innerHTML; };

  async function hashContent(text) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  function sendToBackground(message) { chrome.runtime.sendMessage(message).catch(() => {}); }

  // ── ELEMENT EXTRACTION ──────────────────────────────────────────────
  function extractSingle(el) {
    const t = el.tagName.toLowerCase(), r = [];
    const push = (type, url, text) => r.push({ elementId: generateElementId(el), type, url, text: (text||"").trim().slice(0,120), isVisible: isElementVisible(el) });
    if (t==="a" && hasValidUrl(el.href)) push(el.hasAttribute("download") ? "download" : "link", el.href, el.innerText);
    else if (t==="form" && hasValidUrl(el.action)) {
      push("form", el.action);
      el.querySelectorAll('button[type="submit"],button:not([type]),input[type="submit"],input[type="image"]').forEach(b => r.push({ elementId: generateElementId(b), type: "submit", url: el.action, text: (b.innerText||b.value||"").trim().slice(0,80), formSubmit: true, isVisible: isElementVisible(b) }));
    } else if (t==="iframe" && hasValidUrl(el.src)) push("iframe", el.src);
    else if (["video","audio","embed"].includes(t) && hasValidUrl(el.src)) push(t, el.src);
    else if (t==="object" && hasValidUrl(el.getAttribute("data"))) push("object", el.getAttribute("data"));
    else if (t==="input" && el.type==="file") r.push({ elementId: generateElementId(el), type: "fileInput", text: el.getAttribute("accept")||"File upload", isVisible: isElementVisible(el) });
    else if ((t==="button"||t==="input") && (el.type==="submit"||el.type==="image"||(t==="button"&&!el.type))) {
      const f = el.closest("form[action]");
      if (f && hasValidUrl(f.action)) r.push({ elementId: generateElementId(el), type: "submit", url: f.action, text: (el.innerText||el.value||"").trim().slice(0,80), formSubmit: true, isVisible: isElementVisible(el) });
    }
    return r;
  }

  function extractAll() {
    const els = [];
    document.querySelectorAll(SELECTOR).forEach(el => { processedNodes.add(el); els.push(...extractSingle(el)); });
    return els;
  }

  function extractFromNodes(nodes) {
    const els = [];
    for (const n of nodes) {
      if (n.nodeType !== Node.ELEMENT_NODE || processedNodes.has(n)) continue;
      processedNodes.add(n);
      els.push(...extractSingle(n));
      if (n.querySelectorAll) n.querySelectorAll(SELECTOR).forEach(c => { if (!processedNodes.has(c)) { processedNodes.add(c); els.push(...extractSingle(c)); } });
    }
    return els;
  }

  // ── TEXT EXTRACTION (from specific nodes, not full DOM) ─────────────
  function extractTextFromNodes(nodes) {
    const chunks = [];
    const walk = (node) => {
      if (node.nodeType === Node.TEXT_NODE) {
        const t = node.textContent?.trim();
        if (t && !RE_SCAN_TAGS.has(node.parentElement?.tagName)) chunks.push(t);
      } else if (node.nodeType === Node.ELEMENT_NODE && !RE_SCAN_TAGS.has(node.tagName) && isElementVisible(node)) {
        for (const child of node.childNodes) walk(child);
      }
    };
    for (const n of nodes) walk(n);
    return chunks.join(" ").slice(0, 3000);
  }

  function extractFullVisibleText() {
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, { acceptNode: n => (!n.parentElement || RE_SCAN_TAGS.has(n.parentElement.tagName) || !isElementVisible(n.parentElement) || !n.textContent.trim()) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT });
    const c = []; let n;
    while ((n = w.nextNode()) && c.join(" ").length < 3000) c.push(n.textContent.trim());
    return c.join(" ");
  }

  // ── TEXT ANALYSIS (runs once per unique content hash) ────────────────
  async function analyzeText(text) {
    if (!text) return;
    const hash = await hashContent(text);
    if (scannedHashes.has(hash)) return; // already scanned this exact content
    scannedHashes.add(hash);

    const threats = []; let idx = 0;
    const add = (type, risk, phrases, ctx, extra) => threats.push({ elementId: `${FRAME_ID}:text-${type}:${idx++}`, type, text: ctx.slice(0,120), riskScore: risk, matchedPhrases: phrases, contextSnippet: ctx.slice(0,300), ...extra });

    // Crypto addresses
    for (const [chain, re] of Object.entries(CRYPTO_RE)) { re.lastIndex = 0; let m; while ((m = re.exec(text)) !== null) { if (chain==='solana' && m[1].length<32) continue; add('cryptoAddress', 75, [`${chain}: ${m[1].slice(0,12)}...${m[1].slice(-6)}`], `Detected ${chain} address: ${m[1]}`, { chain }); } }

    // Scam phrases
    const matched = [], cats = new Set();
    for (const { re, cat } of SCAM_PATTERNS) { re.lastIndex = 0; let m; while ((m = re.exec(text)) !== null) { matched.push(m[0]); cats.add(cat); } }
    if (matched.length) add('textThreat', Math.min(100, matched.length * 12), matched.slice(0,5), `Detected ${[...cats].join(', ')} language`, { scamCategories: [...cats] });

    // Homoglyphs
    if (/[\u0400-\u04FF\u0370-\u03FF]/.test(text.replace(/[a-zA-Z]/g, ''))) add('textThreat', 85, ['Homoglyph characters detected'], 'Lookalike Unicode characters (possible IDN homograph attack)');

    // Phishing forms
    document.querySelectorAll('input:not([type=hidden]):not([type=submit])').forEach(input => {
      const combined = ((input.labels?.[0]?.textContent||'') + ' ' + (input.placeholder||'') + ' ' + (input.name||'')).toLowerCase();
      for (const kw of SENSITIVE_KW) { if (combined.includes(kw)) { add('phishingForm', 95, [kw], `Form field requests "${kw}" — ${input.placeholder||input.name||'unnamed'}`, { contextSnippet: `Label: "${input.labels?.[0]?.textContent||'none'}", Placeholder: "${input.placeholder||'none'}"` }); break; } }
    });

    if (threats.length) sendToBackground({ type: 'TEXT_THREATS', threats, pageUrl: location.href, pageText: text.slice(0, 2000) });
  }

  // ── MUTATION OBSERVER (single, handles elements + text + cleanup) ──
  function startObserver() {
    const observer = new MutationObserver(mutations => {
      const added = [], removed = [];
      let hasTextNodes = false;
      for (const m of mutations) {
        if (m.type === "childList") {
          for (const n of m.addedNodes) {
            added.push(n);
            if (!hasTextNodes && n.nodeType === Node.ELEMENT_NODE) {
              // Check if added node contains text content (not just script/style)
              if (n.querySelector?.('p,span,div,td,li,h1,h2,h3,h4,h5,h6,a,button,label') || (!RE_SCAN_TAGS.has(n.tagName) && n.textContent?.trim())) hasTextNodes = true;
            }
          }
          for (const n of m.removedNodes) removed.push(n);
        }
      }
      if (added.length === 0 && removed.length === 0) return;

      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        // Process added elements
        if (added.length) {
          const newEls = extractFromNodes(added);
          // Text scan: only when text-bearing nodes are added
          if (hasTextNodes) {
            const newText = extractTextFromNodes(added);
            if (newText.length > 20) analyzeText(newText);
          }
          if (newEls.length) {
            const vis = [], off = [];
            for (const el of newEls) (el.isVisible ? vis : off).push(el);
            if (vis.length) sendToBackground({ type: "NEW_ELEMENTS", elements: vis, priority: "high" });
            if (off.length) sendToBackground({ type: "NEW_ELEMENTS", elements: off, priority: "low" });
          }
        }
        // Clean up bubbles for removed elements
        if (removed.length) {
          for (const id of [...activeBubbleIds]) {
            const xpath = getXPathFromId(id);
            if (!evaluateXPath(xpath)) {
              document.getElementById(`ss-bubble-${id}`)?.remove();
              activeBubbleIds.delete(id);
            }
          }
        }
      }, 1500);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  // ── CHAT BUBBLE UI ──────────────────────────────────────────────────
  function showOrUpdateBubble(elementId, data) {
    if (data.status === "safe") { document.getElementById(`ss-bubble-${elementId}`)?.remove(); activeBubbleIds.delete(elementId); restoreElement(elementId); return; }
    if (data.riskScore >= 70) disableElement(elementId, data);

    let bubble = document.getElementById(`ss-bubble-${elementId}`);
    if (!bubble) {
      bubble = document.createElement("div");
      bubble.id = `ss-bubble-${elementId}`;
      bubble.style.cssText = `position:absolute;z-index:2147483647;background:#1a1a2e;border:2px solid ${data.riskScore>=70?'#e63946':'#ffc107'};border-radius:8px;padding:12px;max-width:320px;color:white;font-family:system-ui,sans-serif;font-size:14px;box-shadow:0 4px 12px rgba(0,0,0,.5);pointer-events:auto`;
      document.body.appendChild(bubble);
      activeBubbleIds.add(elementId);
    }

    const short = escapeHtml(data.shortExplanation || "This element is dangerous. Proceed with extreme caution.");
    const long = escapeHtml(data.longExplanation || "Loading detailed analysis...");
    const border = data.riskScore >= 70;

    bubble.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px"><strong style="color:${border?'#e63946':'#ffc107'}">⚠️ Risk: ${data.riskScore}/100</strong><button onclick="document.getElementById('ss-bubble-${elementId}').remove()" style="background:none;border:none;color:white;cursor:pointer;margin-left:8px;font-size:1.2em">✕</button></div><p style="margin:0 0 10px;color:#ccc;line-height:1.4;font-size:.95em">${short}</p><div id="ss-long-${elementId}" style="display:none;margin:0 0 10px;padding:8px;border-top:1px solid #444;color:#aaa;font-size:.85em;line-height:1.4">${long}</div><div style="display:flex;gap:8px;align-items:center"><a href="#" id="ss-visit-${elementId}" target="_blank" style="flex:1;padding:6px 12px;background:${border?'#e63946':'#ffc107'};border:none;border-radius:4px;color:white;text-align:center;text-decoration:none;font-size:.9em;cursor:pointer">Visit Anyway</a><a href="#" id="ss-explain-${elementId}" style="padding:6px 12px;background:transparent;border:1px solid #4dabf7;border-radius:4px;color:#4dabf7;text-decoration:none;font-size:.9em;cursor:pointer">Explain more</a></div>`;

    positionBubble(elementId, bubble);

    const visit = bubble.querySelector(`#ss-visit-${elementId}`);
    if (visit) visit.onclick = e => { e.preventDefault(); if (restoreElement(elementId) && data.url) window.open(data.url, '_blank'); else if (data.url) window.open(data.url, '_blank'); bubble.remove(); activeBubbleIds.delete(elementId); };

    const explain = bubble.querySelector(`#ss-explain-${elementId}`);
    if (explain) explain.onclick = e => { e.preventDefault(); const d = bubble.querySelector(`#ss-long-${elementId}`); if (d) { const h = d.style.display==="none"; d.style.display = h ? "block" : "none"; explain.textContent = h ? "Show less" : "Explain more"; } };
  }

  function positionBubble(id, bubble) {
    const el = evaluateXPath(getXPathFromId(id));
    if (el) { const r = el.getBoundingClientRect(); bubble.style.top = `${r.bottom + scrollY + 5}px`; bubble.style.left = `${r.left + scrollX}px`; }
    else { bubble.style.top = `${scrollY + 100}px`; bubble.style.right = "20px"; }
  }

  // ── CLICK INTERCEPTION ──────────────────────────────────────────────
  document.addEventListener("click", e => {
    const t = e.target.closest("a[href],form[action],input[type=submit],input[type=image]");
    if (!t) return;
    const r = elementRiskMap[generateElementId(t)];
    if (r && r.status === "unsafe" && r.riskScore >= 70) { e.preventDefault(); e.stopImmediatePropagation(); showOrUpdateBubble(generateElementId(t), r); }
  }, true);

  // ── SCROLL: reposition only active bubbles ──────────────────────────
  let rafId;
  const onScroll = () => { cancelAnimationFrame(rafId); rafId = requestAnimationFrame(() => { for (const id of activeBubbleIds) { const b = document.getElementById(`ss-bubble-${id}`); if (b) positionBubble(id, b); } }); };
  addEventListener('scroll', onScroll, { capture: true, passive: true });
  addEventListener('resize', onScroll);

  // ── ELEMENT DISABLE / RESTORE ───────────────────────────────────────
  function disableElement(elementId, data) {
    const el = evaluateXPath(getXPathFromId(elementId));
    if (!el || el.dataset.ssDisabled === "true") return;
    const t = el.tagName.toLowerCase();
    if (t==='a' && el.href) { el.dataset.ssOrigHref=el.href; el.dataset.ssOrigTarget=el.target; el.dataset.ssOrigRel=el.rel; el.removeAttribute('href'); el.style.cssText+=';cursor:not-allowed;color:#999;text-decoration:line-through'; }
    else if (t==='input' && el.type==='file') { el.disabled=true; const w=document.createElement('span'); w.textContent='File upload blocked (dangerous)'; w.style.cssText='color:#e63946;font-size:.9em'; el.parentNode.insertBefore(w,el); el.dataset.ssPlaceholder='true'; }
    else if (['iframe','video','audio','embed','object'].includes(t)) { el.dataset.ssOrigSrc=el.src||el.getAttribute('data'); el.style.display='none'; const w=document.createElement('div'); w.textContent='Embedded content blocked (dangerous)'; w.style.cssText='color:#e63946;font-size:.9em;padding:4px 0'; el.parentNode.insertBefore(w,el); el.dataset.ssPlaceholder='true'; }
    else if (t==='form' && el.action) { el.dataset.ssOrigAction=el.action; el.onsubmit=e=>{e.preventDefault();showOrUpdateBubble(elementId,data);return false;}; const b=el.querySelector('button[type="submit"],button:not([type]),input[type="submit"]'); if(b){b.disabled=true;b.style.opacity='0.5';} }
    el.dataset.ssDisabled = "true";
  }

  function restoreElement(elementId) {
    const el = evaluateXPath(getXPathFromId(elementId));
    if (!el || el.dataset.ssDisabled !== "true") return false;
    const t = el.tagName.toLowerCase();
    if (t==='a') { if(el.dataset.ssOrigHref) el.setAttribute('href',el.dataset.ssOrigHref); if(el.dataset.ssOrigTarget) el.target=el.dataset.ssOrigTarget; if(el.dataset.ssOrigRel) el.rel=el.dataset.ssOrigRel; el.style.cssText=el.style.cssText.replace(/cursor:\s*not-allowed;?/g,''); el.style.color=''; el.style.textDecoration=''; }
    else if (t==='input' && el.type==='file') { el.disabled=false; if(el.dataset.ssPlaceholder){const p=el.previousSibling;if(p?.textContent?.includes('blocked'))p.remove();} }
    else if (['iframe','video','audio','embed','object'].includes(t)) { if(el.dataset.ssOrigSrc){['iframe','video','audio'].includes(t)?el.src=el.dataset.ssOrigSrc:el.setAttribute('data',el.dataset.ssOrigSrc);} el.style.display=''; if(el.dataset.ssPlaceholder){const p=el.previousSibling;if(p?.textContent?.includes('blocked'))p.remove();} }
    else if (t==='form') { if(el.dataset.ssOrigAction) el.action=el.dataset.ssOrigAction; const b=el.querySelector('button[type="submit"],button:not([type]),input[type="submit"]'); if(b){b.disabled=false;b.style.opacity='1';} }
    delete el.dataset.ssDisabled;
    return true;
  }

  // ── MESSAGE BUS ─────────────────────────────────────────────────────
  chrome.runtime.onMessage.addListener(msg => {
    if (msg.type === "ELEMENT_UPDATE") {
      elementRiskMap[msg.elementId] = msg.data;
      msg.data.status === "unsafe" ? showOrUpdateBubble(msg.elementId, msg.data) : document.getElementById(`ss-bubble-${msg.elementId}`)?.remove();
    } else if (msg.type === "RESTORE_ELEMENT") { restoreElement(msg.elementId); }
  });

  // ── CLIPBOARD HIJACK MONITOR ────────────────────────────────────────
  const cryptoAddrRe = /0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71}|T[A-Za-z1-9]{33}/i;
  let lastCopy = null;

  document.addEventListener('copy', () => {
    const sel = getSelection().toString().trim();
    if (sel && cryptoAddrRe.test(sel)) lastCopy = { text: sel, time: Date.now() };
  }, true);

  document.addEventListener('paste', e => {
    if (!lastCopy) return;
    const pasted = (e.clipboardData || window.clipboardData).getData('text').trim();
    if (Date.now() - lastCopy.time < 30000 && lastCopy.text !== pasted && cryptoAddrRe.test(pasted)) {
      e.preventDefault(); e.stopImmediatePropagation();
      sendToBackground({ type: 'TEXT_THREATS', threats: [{ elementId: `${FRAME_ID}:clipboard-hijack:${Date.now()}`, type: 'clipboardHijack', text: `Address swapped: ${lastCopy.text.slice(0,16)}... → ${pasted.slice(0,16)}...`, riskScore: 100, matchedPhrases: ['Clipboard hijacking detected'], contextSnippet: `Copied: ${lastCopy.text}\nSwapped to: ${pasted}` }], pageUrl: location.href, pageText: '' });
      lastCopy = null;
    }
  }, true);

  // ── INIT ────────────────────────────────────────────────────────────
  function init() {
    const context = { url: location.href, title: document.title, visibleText: extractFullVisibleText(), timestamp: Date.now(), elements: extractAll() };
    sendToBackground({ type: "PAGE_LOADED", context });
    startObserver();
    // Initial text scan — uses hash so it only runs once
    analyzeText(context.visibleText);
  }

  return { init };
})();

ScamShieldScanner.init();

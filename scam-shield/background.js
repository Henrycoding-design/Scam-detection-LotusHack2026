// background.js
// Built-in API keys (server-side, not user-visible)
const API_KEYS = {
  GOOGLE_SAFE_BROWSING: "BUILTIN_GSB_KEY_PLACEHOLDER",
  VIRUSTOTAL: "BUILTIN_VT_KEY_PLACEHOLDER",
  OPENROUTER: "BUILTIN_OPENROUTER_KEY_PLACEHOLDER",
  OPENAI: "BUILTIN_OPENAI_KEY_PLACEHOLDER",
};

// Free tier URLs (manifest needs host_permissions for these)
const APIS = {
  GSB: "https://safebrowsing.googleapis.com/v4/threatMatches:find",
  VT_URL: "https://www.virustotal.com/api/v3/urls",
  OPENROUTER: "https://openrouter.ai/api/v1/chat/completions",
  OPENAI_MOD: "https://api.openai.com/v1/moderations",
  VERITAS: "https://spam.audent.ai/check",
};

// Allow content scripts to access session storage
chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS' });

// IndexedDB setup
const DB_NAME = "ScamShieldDB";
const STORE_NAME = "pageElements";
let db = null;

// Dashboard connections (tabId -> Set of ports)
const dashboardPorts = new Map();

async function openDB() {
  if (db) return db;
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "key" });
      }
    };
    request.onsuccess = (event) => {
      db = event.target.result;
      resolve(db);
    };
    request.onerror = (event) => reject(event.target.error);
  });
}

// Get all element records for a specific tab
async function getAllElementsForTab(tabId) {
  const database = await openDB();
  return new Promise((resolve, reject) => {
    const tx = database.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const result = new Map();
    const request = store.openCursor();
    request.onsuccess = (e) => {
      const cursor = e.target.result;
      if (cursor) {
        const record = cursor.value;
        if (record.tabId === tabId) {
          result.set(record.elementId, record);
        }
        cursor.continue();
      } else {
        resolve(result);
      }
    };
    request.onerror = (e) => reject(e);
  });
}

async function updateElement(tabId, elementId, updates) {
  const database = await openDB();
  const key = `${tabId}:${elementId}`;
  const tx = database.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  
  const getReq = store.get(key);
  getReq.onsuccess = () => {
    const existing = getReq.result;
    if (existing) {
      const merged = { ...existing, ...updates };
      store.put(merged);
      
      // Send update to content script, targeting the correct frame
      const frameId = existing.chromeFrameId;
      const options = frameId !== undefined ? { frameId } : {};
      chrome.tabs.sendMessage(tabId, {
        type: "ELEMENT_UPDATE",
        elementId,
        data: merged
      }, options).catch(() => {});

      // Broadcast to dashboard ports
      const dashSet = dashboardPorts.get(tabId);
      if (dashSet) {
        dashSet.forEach(port => {
          try {
            port.postMessage({
              type: "ELEMENT_UPDATE",
              elementId,
              data: merged
            });
          } catch (e) {}
        });
      }
    }
  };
}

// Track last clear time per tab to deduplicate rapid clears
const lastClearTime = new Map();

async function clearTabData(tabId) {
  const now = Date.now();
  const last = lastClearTime.get(tabId);
  // Deduplicate: skip if cleared within the last 200ms
  if (last && now - last < 200) return;
  lastClearTime.set(tabId, now);

  const database = await openDB();
  const tx = database.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  const cursor = store.openCursor();
  cursor.onsuccess = (e) => {
    const cursor = e.target.result;
    if (cursor) {
      if (cursor.key.startsWith(`${tabId}:`)) {
        cursor.delete();
      }
      cursor.continue();
    }
  };
  // Notify dashboard ports that this tab's data was cleared
  const dashSet = dashboardPorts.get(tabId);
  if (dashSet) {
    dashSet.forEach(port => {
      try { port.postMessage({ type: 'TAB_CLEARED', tabId }); } catch {}
    });
  }
}

// Google Safe Browsing API
async function checkGoogleSafeBrowsing(url) {
  try {
    const body = {
      client: { clientId: "scamshield", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    
    const response = await fetch(`${APIS.GSB}?key=${API_KEYS.GOOGLE_SAFE_BROWSING}`, {
      method: "POST",
      body: JSON.stringify(body)
    });
    
    if (!response.ok) return { status: "error", score: 0, source: "gsb" };
    
    const data = await response.json();
    if (data.matches && data.matches.length > 0) {
      return { 
        status: "unsafe", 
        score: 90, 
        source: "gsb",
        details: data.matches.map(m => m.threatType).join(", ")
      };
    }
    return { status: "safe", score: 0, source: "gsb" };
  } catch (error) {
    return { status: "error", score: 0, source: "gsb", error: error.message };
  }
}

// VirusTotal API — fire-and-forget: submit URL, return pending immediately
async function checkVirusTotal(url) {
  try {
    const submitRes = await fetch(APIS.VT_URL, {
      method: "POST",
      headers: { "x-apikey": API_KEYS.VIRUSTOTAL },
      body: JSON.stringify({ url })
    });

    if (!submitRes.ok) {
      const errorText = await submitRes.text().catch(() => "Unknown error");
      return { status: "error", score: 0, source: "vt", error: `VT submit: ${submitRes.status} - ${errorText.substring(0, 100)}` };
    }

    const submitData = await submitRes.json();
    return { status: "pending", source: "vt", analysisId: submitData.data.id };
  } catch (error) {
    return { status: "error", score: 0, source: "vt", error: error.message };
  }
}

// Event-driven VT result check via chrome.alarms (survives service worker restart)
function scheduleVTCheck(tabId, elementId, analysisId, delayMs) {
  const alarmName = `vt:${tabId}:${elementId}`;
  chrome.alarms.create(alarmName, { delayInMinutes: Math.max(delayMs / 60000, 0.05) });
  // Store context in session storage for the alarm handler
  chrome.storage.session.set({ [alarmName]: { tabId, elementId, analysisId } });
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (!alarm.name.startsWith('vt:')) return;
  const ctx = await chrome.storage.session.get(alarm.name);
  const data = ctx[alarm.name];
  if (!data) return;
  chrome.storage.session.remove(alarm.name);
  fetchVTResult(data.tabId, data.elementId, data.analysisId);
});

async function fetchVTResult(tabId, elementId, analysisId) {
  try {
    const analysisRes = await fetch(`${APIS.VT_URL}/${analysisId}`, {
      headers: { "x-apikey": API_KEYS.VIRUSTOTAL }
    });

    if (!analysisRes.ok) {
      if (analysisRes.status === 404 || analysisRes.status === 202) {
        const retryAfter = analysisRes.headers.get("Retry-After");
        const waitMs = retryAfter ? Math.min(parseInt(retryAfter) * 1000, 15000) : 5000;
        scheduleVTCheck(tabId, elementId, analysisId, waitMs);
        return;
      }
      await updateElement(tabId, elementId, {
        status: "error", source: "vt",
        shortExplanation: "VT scan failed.",
        longExplanation: `VirusTotal returned status ${analysisRes.status}.`
      });
      return;
    }

    const analysisData = await analysisRes.json();
    const stats = analysisData.data.attributes.last_analysis_stats;
    const malicious = stats?.malicious || 0;
    const suspicious = stats?.suspicious || 0;

    if (malicious > 0 || suspicious > 0) {
      const score = Math.min(100, (malicious * 20) + (suspicious * 10));
      await updateElement(tabId, elementId, {
        status: "unsafe", riskScore: score, source: "vt",
        details: `${malicious} malicious, ${suspicious} suspicious detections`,
        shortExplanation: `Dangerous: ${malicious} malicious detections`,
        longExplanation: `VirusTotal flagged this element with ${malicious} malicious and ${suspicious} suspicious detections across multiple engines. It is recommended to avoid interacting with it.`
      });
    } else {
      await updateElement(tabId, elementId, {
        status: "safe", riskScore: 0, source: "vt",
        shortExplanation: "Safe",
        longExplanation: "This element passed VirusTotal security checks."
      });
    }
  } catch (error) {
    scheduleVTCheck(tabId, elementId, analysisId, 5000);
  }
}

// AI fallback with OpenRouter (stepfun/step-3.5-flash:free)
async function generateAIExplanation(url, type, contextText, existingDetails = "") {
  try {
    const systemPrompt = `You are a security analyst. Given a URL and its context, generate two explanations: 
1) SHORT (max 15 words): why it might be dangerous
2) LONG (max 100 words): detailed reasoning
    
Return JSON: {"short": "...", "long": "..."}. Be concise and factual.`;

    const userMessage = `URL: ${url}\nType: ${type}\nPage context excerpt: ${contextText.substring(0, 500)}\nScan results: ${existingDetails}`;

    const response = await fetch(APIS.OPENROUTER, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${API_KEYS.OPENROUTER}`,
        "Content-Type": "application/json",
        "HTTP-Referer": "https://scamshield.extension", // required by OpenRouter
        "X-Title": "ScamShield Extension"
      },
      body: JSON.stringify({
        model: "stepfun/step-3.5-flash:free",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userMessage }
        ],
        temperature: 0.3,
        max_tokens: 200
      })
    });

    if (!response.ok) throw new Error(`OpenRouter error: ${response.status}`);
    
    const data = await response.json();
    const content = data.choices?.[0]?.message?.content || "{}";
    
    try {
      const parsed = JSON.parse(content);
      return {
        shortExplanation: parsed.short || "Potentially unsafe based on AI analysis.",
        longExplanation: parsed.long || "This element has been flagged as potentially dangerous. Exercise caution when interacting with it."
      };
    } catch (e) {
      return {
        shortExplanation: "Potentially unsafe (AI analysis pending).",
        longExplanation: "AI explanation could not be generated. The element shows risk indicators."
      };
    }
  } catch (error) {
    return {
      shortExplanation: "AI explanation unavailable.",
      longExplanation: `Error generating explanation: ${error.message}`
    };
  }
}

// OpenAI Moderation API — FREE, unlimited, ~200ms
async function checkOpenAIModeration(text) {
  try {
    if (!text || API_KEYS.OPENAI === "BUILTIN_OPENAI_KEY_PLACEHOLDER")
      return { flagged: false, score: 0, categories: {} };
    const res = await fetch(APIS.OPENAI_MOD, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${API_KEYS.OPENAI}` },
      body: JSON.stringify({ input: text.slice(0, 2000), model: "omni-moderation-latest" }),
    });
    if (!res.ok) return { flagged: false, score: 0, categories: {} };
    const data = await res.json();
    const r = data.results?.[0] || {};
    const cats = r.categories || {};
    const flaggedCats = Object.entries(cats).filter(([, v]) => v).map(([k]) => k);
    return {
      flagged: r.flagged || false,
      score: r.flagged ? 85 : 0,
      categories: flaggedCats,
      details: flaggedCats.join(', '),
    };
  } catch { return { flagged: false, score: 0, categories: {} }; }
}

// Veritas AI (otis model) — 500 free requests/day, ~400ms
async function checkVeritasAI(text) {
  try {
    const res = await fetch(APIS.VERITAS, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: text.slice(0, 1500), model: "otis" }),
    });
    if (!res.ok) return { isSpam: false, score: 0 };
    const data = await res.json();
    const spamScore = data.spam_score ?? data.score ?? 0;
    return {
      isSpam: spamScore > 0.6,
      score: Math.round(spamScore * 100),
      details: data.prediction || data.label || '',
    };
  } catch { return { isSpam: false, score: 0 }; }
}

// Handle text threats from content script — store + escalate to APIs
async function handleTextThreats(threats, pageUrl, pageText, tabId, frameId) {
  if (!tabId || !threats?.length) return;
  console.log(`[ScamShield] Text threats: ${threats.length} from ${pageUrl}`);

  // Run API checks concurrently on the page text
  const [openaiResult, veritasResult] = await Promise.allSettled([
    pageText ? checkOpenAIModeration(pageText) : Promise.resolve({ flagged: false, score: 0 }),
    pageText ? checkVeritasAI(pageText) : Promise.resolve({ isSpam: false, score: 0 }),
  ]);
  const openai = openaiResult.status === 'fulfilled' ? openaiResult.value : { flagged: false, score: 0 };
  const veritas = veritasResult.status === 'fulfilled' ? veritasResult.value : { isSpam: false, score: 0 };

  // Build all threat records first, then write in a single transaction
  const records = [];
  for (const threat of threats) {
    const localScore = threat.riskScore || 0;
    const apiMax = Math.max(openai.score || 0, veritas.score || 0);
    const combined = Math.min(100, Math.round(localScore * 0.6 + apiMax * 0.4));

    let status = 'safe', source = 'local', details = '';
    if (localScore >= 80 || openai.flagged || veritas.isSpam) {
      status = 'unsafe';
      source = openai.flagged ? 'openai' : veritas.isSpam ? 'veritas' : 'local';
      details = [
        openai.flagged ? `OpenAI: ${openai.details}` : '',
        veritas.isSpam ? `Veritas: ${veritas.details}` : '',
        threat.matchedPhrases?.length ? `Patterns: ${threat.matchedPhrases.join(', ')}` : '',
      ].filter(Boolean).join(' | ');
    } else if (localScore >= 40) {
      status = 'unsafe';
      source = 'local';
      details = threat.matchedPhrases?.join(', ') || threat.text || '';
    }

    records.push({
      key: `${tabId}:${threat.elementId}`,
      tabId, elementId: threat.elementId, type: threat.type,
      url: null, text: threat.text || '',
      timestamp: Date.now(), status, riskScore: combined,
      shortExplanation: status === 'unsafe'
        ? `Detected: ${threat.matchedPhrases?.[0] || threat.type}`
        : 'No threats detected',
      longExplanation: status === 'unsafe'
        ? `This ${threat.type.replace(/([A-Z])/g, ' $1').toLowerCase()} was flagged: ${details || 'suspicious patterns found'}. Exercise caution.`
        : 'Content passed text analysis checks.',
      source, details: details || threat.contextSnippet || '',
      chromeFrameId: frameId,
      matchedPhrases: threat.matchedPhrases || [],
      contextSnippet: threat.contextSnippet || '',
    });
  }

  // Write all records in a single transaction
  const database = await openDB();
  const tx = database.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  for (const rec of records) {
    store.delete(rec.key);
    store.put(rec);
  }
  await new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = rej; });

  // Broadcast all to dashboard in one batch
  const dashSet = dashboardPorts.get(tabId);
  if (dashSet) {
    for (const rec of records) {
      const broadcast = {
        elementId: rec.elementId, tabId, type: rec.type, text: rec.text,
        status: rec.status, riskScore: rec.riskScore, source: rec.source,
        details: rec.details, shortExplanation: rec.shortExplanation,
        longExplanation: rec.status === 'unsafe' ? `Flagged: ${rec.details || 'suspicious patterns'}` : 'Content passed checks.',
        timestamp: rec.timestamp, matchedPhrases: rec.matchedPhrases,
        contextSnippet: rec.contextSnippet,
      };
      dashSet.forEach(port => {
        try { port.postMessage({ type: 'ELEMENT_UPDATE', elementId: rec.elementId, data: broadcast }); } catch {}
      });
    }
  }
}

async function handleScan(context, tabId, frameId) {
  if (!tabId) {
    console.warn("[ScamShield] No tabId, cannot send updates");
    return;
  }
  
  console.log("[ScamShield] Scanning:", context.url);
  console.log(`  → ${context.elements.length} elements found`);
  
  const scanned = await storeAndDiffElements(context.elements, tabId, frameId);
  await scanElements(scanned.urlElements, scanned.nonUrlElements, tabId, context.visibleText);
}

// Handle incremental elements from MutationObserver (NEW_ELEMENTS message)
async function handleNewElements(elements, tabId, frameId) {
  if (!tabId || !elements || elements.length === 0) return;
  console.log(`[ScamShield] Incremental: ${elements.length} new elements`);

  const scanned = await storeAndDiffElements(elements, tabId, frameId);
  // No visibleText for incremental scans — skip AI explanations, rely on GSB/VT
  await scanElements(scanned.urlElements, scanned.nonUrlElements, tabId, "");
}

// Shared: diff against IndexedDB, store pending records, return categorized elements
async function storeAndDiffElements(elements, tabId, frameId) {
  const database = await openDB();
  const existingMap = await getAllElementsForTab(tabId);

  const elementsToScan = elements.filter(el => {
    const existing = existingMap.get(el.elementId);
    if (!existing) return true;
    if (existing.status === "pending") return true;
    if (existing.status === "safe" || existing.status === "unsafe") {
      if (existing.url !== (el.url || null) || existing.text !== (el.text || "")) return true;
      return false;
    }
    return true;
  });

  console.log(`[ScamShield] Elements to scan: ${elementsToScan.length} (new/changed)`);

  // Store pending records
  const tx = database.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  for (const el of elementsToScan) {
    store.delete(`${tabId}:${el.elementId}`);
    store.put({
      key: `${tabId}:${el.elementId}`,
      tabId, elementId: el.elementId, type: el.type,
      url: el.url || null, text: el.text || "",
      timestamp: Date.now(), status: "pending", riskScore: 0,
      shortExplanation: "", longExplanation: "",
      source: null, details: "", chromeFrameId: frameId
    });
  }
  await new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = reject;
  });

  return {
    urlElements: elementsToScan.filter(el => el.url),
    nonUrlElements: elementsToScan.filter(el => !el.url)
  };
}

// Fire-and-forget AI explanation update for unsafe elements
function fireAIExplanation(tabId, element, contextText, details) {
  if (!contextText) return;
  generateAIExplanation(element.url, element.type, contextText, details)
    .then(ai => updateElement(tabId, element.elementId, ai))
    .catch(() => {});
}

// Shared: concurrent batch scanning for URL elements, mark non-URL as safe
async function scanElements(urlElements, nonUrlElements, tabId, contextText) {
  // Process non-URL elements concurrently (form submissions without standalone URL)
  await Promise.allSettled(nonUrlElements.map(element =>
    updateElement(tabId, element.elementId, {
      status: "safe", riskScore: 0, source: "manual",
      shortExplanation: "Safe (form submission, no standalone URL)",
      longExplanation: "This element submits to a form action that has been scanned separately."
    })
  ));

  // Process ALL URL elements concurrently in batches (all batches fire in parallel)
  const BATCH_SIZE = 20;
  const batches = [];
  for (let i = 0; i < urlElements.length; i += BATCH_SIZE) {
    batches.push(urlElements.slice(i, i + BATCH_SIZE));
  }
  await Promise.all(batches.map(batch => {
    return Promise.allSettled(batch.map(async (element) => {
      // Run both GSB and VT concurrently for this URL
      const [gsbResult, vtResult] = await Promise.allSettled([
        checkGoogleSafeBrowsing(element.url),
        checkVirusTotal(element.url)
      ]);

      const gsb = gsbResult.status === "fulfilled" ? gsbResult.value : { status: "error" };
      const vt = vtResult.status === "fulfilled" ? vtResult.value : { status: "error" };

      // If GSB flags unsafe, mark immediately — don't wait for VT
      if (gsb.status === "unsafe") {
        await updateElement(tabId, element.elementId, {
          status: "unsafe", riskScore: gsb.score, source: "gsb",
          details: `GSB: ${gsb.details}`,
          shortExplanation: `Dangerous: ${gsb.details}`,
          longExplanation: `This ${element.type} has been flagged by Google Safe Browsing: ${gsb.details}. It is recommended to avoid interacting with it.`
        });
        fireAIExplanation(tabId, element, contextText, `GSB: ${gsb.details}`);
        if (vt.status === "pending" && vt.analysisId) scheduleVTCheck(tabId, element.elementId, vt.analysisId, 5000);
        return;
      }

      // If VT submitted successfully, mark as pending and check result later
      if (vt.status === "pending" && vt.analysisId) {
        await updateElement(tabId, element.elementId, {
          status: "pending", riskScore: 0, source: "vt",
          shortExplanation: "Scanning via VirusTotal...",
          longExplanation: "This element is being analyzed by VirusTotal. Results will appear shortly."
        });
        scheduleVTCheck(tabId, element.elementId, vt.analysisId, 5000);
        return;
      }

      // Both scanners returned final results — check if either flagged unsafe
      if (vt.status === "unsafe") {
        const details = `VT: ${vt.details}`;
        await updateElement(tabId, element.elementId, {
          status: "unsafe", riskScore: vt.score, source: "vt",
          details,
          shortExplanation: `Dangerous: ${vt.details}`,
          longExplanation: `This ${element.type} has been flagged by security services: ${details}. It is recommended to avoid interacting with it.`
        });
        fireAIExplanation(tabId, element, contextText, details);
      } else {
        await updateElement(tabId, element.elementId, {
          status: "safe", riskScore: 0,
          source: gsb.status === "safe" ? "gsb" : vt.status === "safe" ? "vt" : "manual",
          shortExplanation: "Safe",
          longExplanation: "This element passed security checks and appears safe."
        });
      }
    }));
  }));
}

// Message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PAGE_LOADED") {
    const tabId = sender.tab?.id;
    const frameId = sender.frameId;
    if (tabId !== undefined && frameId !== undefined) {
      handleScan(message.context, tabId, frameId).catch(console.error);
    }
  } else if (message.type === "NEW_ELEMENTS") {
    const tabId = sender.tab?.id;
    const frameId = sender.frameId;
    if (tabId !== undefined) {
      handleNewElements(message.elements, tabId, frameId).catch(console.error);
    }
  } else if (message.type === "TEXT_THREATS") {
    const tabId = sender.tab?.id;
    const frameId = sender.frameId;
    if (tabId !== undefined) {
      handleTextThreats(message.threats, message.pageUrl, message.pageText, tabId, frameId).catch(console.error);
    }
  } else if (message.type === "PAGE_NAVIGATING") {
    const tabId = sender.tab?.id;
    if (tabId !== undefined) {
      clearTabData(tabId);
    }
  } else if (message.type === "GET_TAB_DATA") {
    const tabId = message.tabId;
    getAllElementsForTab(tabId).then(elements => {
      sendResponse({ elements: Array.from(elements.values()) });
    }).catch(() => {
      sendResponse({ elements: [] });
    });
    return true;
  } else if (message.type === "RESTORE_ELEMENT") {
    // Use tabId from message (sent by dashboard), fallback to sender
    const tabId = message.tabId || sender.tab?.id;
    if (tabId !== undefined) {
      // Forward to content script (all frames)
      chrome.tabs.sendMessage(tabId, {
        type: "RESTORE_ELEMENT",
        elementId: message.elementId
      }).catch(() => {});
      sendResponse({ success: true });
    }
    return true;
  }
  return false;
});

// Dashboard port connection handler
chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== 'dashboard') return;
  let activeTabId = null;

  port.onMessage.addListener((msg) => {
    if (msg.type === 'INIT_DASHBOARD') {
      activeTabId = msg.tabId;
      if (!dashboardPorts.has(activeTabId)) {
        dashboardPorts.set(activeTabId, new Set());
      }
      dashboardPorts.get(activeTabId).add(port);
      port.onDisconnect.addListener(() => {
        if (activeTabId !== null) {
          const set = dashboardPorts.get(activeTabId);
          if (set) {
            set.delete(port);
            if (set.size === 0) dashboardPorts.delete(activeTabId);
          }
        }
      });
    } else if (msg.type === 'ACTIVE_TAB_CHANGED') {
      // Unregister from old tab
      if (activeTabId !== null) {
        const oldSet = dashboardPorts.get(activeTabId);
        if (oldSet) { oldSet.delete(port); if (oldSet.size === 0) dashboardPorts.delete(activeTabId); }
      }
      activeTabId = msg.tabId;
      // Register for new tab
      if (!dashboardPorts.has(activeTabId)) dashboardPorts.set(activeTabId, new Set());
      dashboardPorts.get(activeTabId).add(port);
      // Send existing data immediately
      getAllElementsForTab(activeTabId).then(elements => {
        try { port.postMessage({ type: 'TAB_DATA', tabId: activeTabId, elements: Array.from(elements.values()) }); } catch {}
      }).catch(() => {});
    }
  });
});

// Download interceptor — proactively scan and block unsafe downloads
chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
  openDB().then(async (database) => {
    // First check IndexedDB for existing scan result
    const tx = database.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const existing = await new Promise((resolve) => {
      const req = store.openCursor();
      req.onsuccess = (e) => {
        const cursor = e.target.result;
        if (cursor) {
          if (cursor.value.url === downloadItem.url && cursor.value.status === "unsafe") {
            resolve(cursor.value);
            return;
          }
          cursor.continue();
        } else resolve(null);
      };
      req.onerror = () => resolve(null);
    });

    if (existing && existing.riskScore >= 70) {
      suggest({ cancel: true });
      return;
    }

    // Proactively scan via Google Safe Browsing
    const gsb = await checkGoogleSafeBrowsing(downloadItem.url);
    if (gsb.status === "unsafe") {
      suggest({ cancel: true });
      return;
    }

    suggest({});
  }).catch(() => suggest({}));
  return true;
});

// Download file tracking — store completed downloads for file:// open interception
chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state?.current === "complete") {
    chrome.downloads.search({ id: delta.id }, (results) => {
      if (results?.[0]) {
        const item = results[0];
        chrome.storage.local.set({
          [`dl_${item.url}`]: { filename: item.filename, url: item.url, time: Date.now() }
        });
      }
    });
  }
});

// file:// navigation interception — block opens of known-dangerous downloaded files
chrome.webNavigation?.onBeforeNavigate?.addListener?.((details) => {
  if (!details.url.startsWith("file://")) return;
  chrome.storage.local.get(null, async (store) => {
    for (const [key, dl] of Object.entries(store)) {
      if (!key.startsWith("dl_")) continue;
      // Match by filename suffix (path separators differ per OS)
      const dlBase = dl.filename?.split(/[\\/]/).pop();
      const navBase = details.url.split(/[\\/]/).pop()?.split("?")[0]?.split("#")[0];
      if (dlBase && navBase && decodeURIComponent(navBase) === dlBase) {
        // Check IndexedDB for existing scan result
        try {
          const database = await openDB();
          const tx = database.transaction(STORE_NAME, "readonly");
          const store2 = tx.objectStore(STORE_NAME);
          const found = await new Promise((resolve) => {
            const req = store2.openCursor();
            req.onsuccess = (e) => {
              const cursor = e.target.result;
              if (cursor) {
                if (cursor.value.url === dl.url && cursor.value.status === "unsafe") { resolve(cursor.value); return; }
                cursor.continue();
              } else resolve(null);
            };
            req.onerror = () => resolve(null);
          });
          if (found) {
            // Block navigation to this file — redirect to a warning page
            chrome.tabs.update(details.tabId, { url: "about:blank" });
            return;
          }
          // If not yet scanned, proactively scan the download URL
          const gsb = await checkGoogleSafeBrowsing(dl.url);
          if (gsb.status === "unsafe") {
            chrome.tabs.update(details.tabId, { url: "about:blank" });
          }
        } catch (e) {}
        break;
      }
    }
  });
}, { url: [{ urlPrefix: "file://" }] });
chrome.tabs.onRemoved.addListener((tabId) => {
  clearTabData(tabId);
  lastClearTime.delete(tabId);
});

// Clear tab data on full page navigations (replaces tabs.onUpdated)
chrome.webNavigation?.onCommitted?.addListener((details) => {
  if (details.frameId === 0) clearTabData(details.tabId);
});

// Clear tab data on SPA navigations (history.pushState / replaceState)
chrome.webNavigation?.onHistoryStateUpdated?.addListener((details) => {
  if (details.frameId === 0) clearTabData(details.tabId);
});

// Clear tab data on hash changes
chrome.webNavigation?.onReferenceFragmentUpdated?.addListener((details) => {
  if (details.frameId === 0) clearTabData(details.tabId);
});

// Fallback: if webNavigation is unavailable
if (!chrome.webNavigation) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === "loading") clearTabData(tabId);
  });
}

// Open side panel when extension icon is clicked
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {});

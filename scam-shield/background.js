// background.js
// Built-in API keys (server-side, not user-visible)
const API_KEYS = {
  GOOGLE_SAFE_BROWSING: "BUILTIN_GSB_KEY_PLACEHOLDER", // Replace with actual GSB API key
  VIRUSTOTAL: "BUILTIN_VT_KEY_PLACEHOLDER", // Replace with actual VT API key
  OPENROUTER: "BUILTIN_OPENROUTER_KEY_PLACEHOLDER" // Replace with actual OpenRouter key
};

// Free tier URLs (manifest needs host_permissions for these)
const APIS = {
  GSB: "https://safebrowsing.googleapis.com/v4/threatMatches:find",
  VT_URL: "https://www.virustotal.com/api/v3/urls",
  OPENROUTER: "https://openrouter.ai/api/v1/chat/completions"
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

async function clearTabData(tabId) {
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

// Event-driven VT result check — single fetch, no polling loop
function scheduleVTCheck(tabId, elementId, analysisId, delayMs) {
  setTimeout(() => fetchVTResult(tabId, elementId, analysisId), delayMs);
}

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

// Main scan handler with concurrency
async function handleScan(context, tabId, frameId) {
  if (!tabId) {
    console.warn("[ScamShield] No tabId, cannot send updates");
    return;
  }
  
  console.log("[ScamShield] Scanning:", context.url);
  console.log(`  → ${context.elements.length} elements found`);
  
  const database = await openDB();
  
  // Get all existing elements for this tab from IndexedDB
  const existingMap = await getAllElementsForTab(tabId);
  
  // Determine which elements need scanning (new or changed)
  const elementsToScan = context.elements.filter(el => {
    const existing = existingMap.get(el.elementId);
    if (!existing) return true;
    // If pending, rescan to ensure completion
    if (existing.status === "pending") return true;
    // If final status but properties changed, rescan
    if (existing.status === "safe" || existing.status === "unsafe") {
      if (existing.url !== (el.url || null) || existing.text !== (el.text || "")) {
        return true;
      }
      return false;
    }
    return true;
  });
  
  console.log(`[ScamShield] Elements to scan: ${elementsToScan.length} (new/changed)`);
  
  // Store pending records for elementsToScan (overwrite any existing)
  const tx = database.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  for (const el of elementsToScan) {
    // Delete any existing record for this elementId
    store.delete(`${tabId}:${el.elementId}`);
    // Put new pending record with frameId
    store.put({
      key: `${tabId}:${el.elementId}`,
      tabId,
      elementId: el.elementId,
      type: el.type,
      url: el.url || null,
      text: el.text || "",
      timestamp: Date.now(),
      status: "pending",
      riskScore: 0,
      shortExplanation: "",
      longExplanation: "",
      source: null,
      details: "",
      chromeFrameId: frameId
    });
  }
  await new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = reject;
  });
  
  // Separate by URL availability
  const urlElements = elementsToScan.filter(el => el.url);
  const nonUrlElements = elementsToScan.filter(el => !el.url);
  
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
        const update = {
          status: "unsafe",
          riskScore: gsb.score,
          source: "gsb",
          details: `GSB: ${gsb.details}`,
          shortExplanation: `Dangerous: ${gsb.details}`,
          longExplanation: `This ${element.type} has been flagged by Google Safe Browsing: ${gsb.details}. It is recommended to avoid interacting with it.`
        };
        await updateElement(tabId, element.elementId, update);
        // Fire-and-forget AI explanation for the popup
        generateAIExplanation(element.url, element.type, context.visibleText, update.details)
          .then(ai => updateElement(tabId, element.elementId, ai))
          .catch(() => {});
        // Still check VT result once in background for additional data
        if (vt.status === "pending" && vt.analysisId) {
          scheduleVTCheck(tabId, element.elementId, vt.analysisId, 5000);
        }
        return;
      }

      // If VT submitted successfully, mark as pending and poll in background
      if (vt.status === "pending" && vt.analysisId) {
        await updateElement(tabId, element.elementId, {
          status: "pending",
          riskScore: 0,
          source: "vt",
          shortExplanation: "Scanning via VirusTotal...",
          longExplanation: "This element is being analyzed by VirusTotal. Results will appear shortly."
        });
        scheduleVTCheck(tabId, element.elementId, vt.analysisId, 5000);
        return;
      }

      // Both scanners returned final results
      const details = [];
      let source = "none";

      if (vt.status === "unsafe") {
        details.push(`VT: ${vt.details}`);
        source = "vt";
      }
      if (gsb.status === "safe" || vt.status === "safe") {
        source = gsb.status === "safe" ? "gsb" : "vt";
      }

      if (vt.status === "unsafe") {
        const update = {
          status: "unsafe",
          riskScore: vt.score,
          source,
          details: details.join(" | "),
          shortExplanation: `Dangerous: ${vt.details}`,
          longExplanation: `This ${element.type} has been flagged by security services: ${details.join(". ")}. It is recommended to avoid interacting with it.`
        };
        await updateElement(tabId, element.elementId, update);
        // Fire-and-forget AI explanation for the popup
        generateAIExplanation(element.url, element.type, context.visibleText, update.details)
          .then(ai => updateElement(tabId, element.elementId, ai))
          .catch(() => {});
      } else {
        await updateElement(tabId, element.elementId, {
          status: "safe",
          riskScore: 0,
          source: source || "manual",
          shortExplanation: "Safe",
          longExplanation: "This element passed security checks and appears safe."
        });
      }
    }));
  }));
  
  // Process non-URL elements as safe with caveat
  for (const element of nonUrlElements) {
    await updateElement(tabId, element.elementId, {
      status: "safe",
      riskScore: 0,
      source: "manual",
      shortExplanation: "Safe (no URL to scan)",
      longExplanation: "This interactive element does not contain a direct URL and requires manual verification."
    });
  }
}

// Message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PAGE_LOADED" || message.type === "PAGE_UPDATED") {
    const tabId = sender.tab?.id;
    const frameId = sender.frameId;
    if (tabId !== undefined && frameId !== undefined) {
      handleScan(message.context, tabId, frameId).catch(console.error);
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
  } else if (message.type === "INIT_DASHBOARD") {
    const tabId = message.tabId;
    if (!dashboardPorts.has(tabId)) {
      dashboardPorts.set(tabId, new Set());
    }
    dashboardPorts.get(tabId).add(sender.port);
    
    sender.port.onDisconnect.addListener(() => {
      const set = dashboardPorts.get(tabId);
      if (set) {
        set.delete(sender.port);
        if (set.size === 0) {
          dashboardPorts.delete(tabId);
        }
      }
    });
  }
  return false;
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

// Tab lifecycle: clear data on navigation/close
chrome.tabs.onRemoved.addListener((tabId) => {
  clearTabData(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    clearTabData(tabId);
  }
});

// Open side panel when extension icon is clicked
chrome.sidePanel
  .setPanelBehavior({ openPanelOnActionClick: true })
  .catch(() => {});

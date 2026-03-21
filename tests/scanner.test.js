import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";

const scannerSource = fs.readFileSync(
  path.resolve("scam-shield/content/scanner.js"),
  "utf8"
);

function createScannerHarness({ historyLength = 2 } = {}) {
  const elementsById = new Map();
  const clickListeners = [];
  const runtimeListeners = [];
  const sentMessages = [];
  let historyBackCalls = 0;
  let windowCloseCalls = 0;
  let timeoutCallCount = 0;

  function makeElement(tagName = "div", extra = {}) {
    return {
      tagName: tagName.toUpperCase(),
      style: {},
      children: [],
      innerText: extra.innerText || "",
      textContent: extra.textContent || "",
      href: extra.href || "",
      id: extra.id || "",
      onclick: null,
      _innerHTML: "",
      remove() {
        if (this.id) {
          elementsById.delete(this.id);
        }
      },
      appendChild(child) {
        this.children.push(child);
      },
      closest(selector) {
        if (selector === "a[href]" && this.href) {
          return this;
        }
        if (selector === "#ss-open-panel" && this.id === "ss-open-panel") {
          return this;
        }
        return null;
      },
      querySelector(selector) {
        if (selector.startsWith("#")) {
          return elementsById.get(selector.slice(1)) || null;
        }
        return null;
      },
      set innerHTML(value) {
        this._innerHTML = value;
      },
      get innerHTML() {
        return this._innerHTML || "";
      },
    };
  }

  const document = {
    title: "Test Page",
    body: {
      style: {},
      appendChild(element) {
        if (element.id) {
          elementsById.set(element.id, element);
        }
        const ids = Array.from(element.innerHTML.matchAll(/id="([^"]+)"/g)).map((match) => match[1]);
        for (const id of ids) {
          elementsById.set(id, makeElement("button", { id }));
        }
      },
    },
    querySelectorAll(selector) {
      if (selector === "meta" || selector === "a[href]") {
        return [];
      }
      return [];
    },
    createTreeWalker() {
      return {
        nextNode() {
          return null;
        },
      };
    },
    addEventListener(type, handler) {
      if (type === "click") {
        clickListeners.push(handler);
      }
    },
    createElement(tagName) {
      return makeElement(tagName);
    },
    getElementById(id) {
      return elementsById.get(id) || null;
    },
  };

  const context = {
    console,
    document,
    MutationObserver: class {
      observe() {}
    },
    NodeFilter: {
      SHOW_TEXT: 4,
      FILTER_REJECT: 2,
      FILTER_ACCEPT: 1,
    },
    chrome: {
      runtime: {
        sendMessage(message) {
          sentMessages.push(message);
          return Promise.resolve();
        },
        onMessage: {
          addListener(listener) {
            runtimeListeners.push(listener);
          },
        },
      },
      storage: {
        session: {
          set() {
            return Promise.resolve();
          },
        },
      },
    },
    window: {
      location: {
        href: "https://example.com",
      },
      history: {
        length: historyLength,
        back() {
          historyBackCalls += 1;
        },
      },
      close() {
        windowCloseCalls += 1;
      },
      getComputedStyle() {
        return {
          display: "block",
          visibility: "visible",
          opacity: "1",
        };
      },
    },
    setTimeout(callback) {
      timeoutCallCount += 1;
      callback();
      return 1;
    },
    clearTimeout() {},
  };

  vm.runInNewContext(scannerSource, context, { filename: "scanner.js" });

  return {
    sentMessages,
    elementsById,
    document,
    get historyBackCalls() {
      return historyBackCalls;
    },
    get windowCloseCalls() {
      return windowCloseCalls;
    },
    get timeoutCallCount() {
      return timeoutCallCount;
    },
    get locationHref() {
      return context.window.location.href;
    },
    triggerClick(target) {
      const event = {
        target,
        preventDefault() {},
        stopPropagation() {},
      };
      clickListeners[0](event);
    },
    triggerRuntimeMessage(message) {
      for (const listener of runtimeListeners) {
        listener(message);
      }
    },
  };
}

test("scanner renders a blocking dangerous page overlay with indicators immediately", () => {
  const harness = createScannerHarness();

  harness.triggerRuntimeMessage({
    type: "PAGE_SCAN_RESULT",
    analysis: {
      subjectType: "page",
      url: "https://phish.example.com",
      score: 75,
      verdict: "dangerous",
      scamType: "credential phishing",
      aiStatus: "pending",
      headline: "Likely Credential Phishing",
      reason: "The page imitates a bank and pressures you to sign in.",
      riskLocation: "The risk is likely in the sign-in form.",
      recommendedAction: "Do not enter your password.",
      preventionTips: ["Type the official site manually.", "Check the domain first."],
      signals: [
        { reason: 'Link impersonates "bank"' },
        { reason: "Suspicious TLD: xyz" },
      ],
    },
  });

  const root = harness.elementsById.get("scamshield-page-warning");
  assert.match(root.innerHTML, /credential phishing/i);
  assert.match(root.innerHTML, /Link impersonates &quot;bank&quot;/);
  assert.match(root.innerHTML, /Analyzing the content/);
  assert.equal(harness.document.body.style.overflow, "hidden");
});

test("scanner updates the page overlay with final AI explanation details", () => {
  const harness = createScannerHarness();

  harness.triggerRuntimeMessage({
    type: "PAGE_EXPLANATION",
    analysis: {
      subjectType: "page",
      url: "https://phish.example.com",
      score: 75,
      verdict: "dangerous",
      scamType: "credential phishing",
      aiStatus: "ready",
      headline: "Likely Credential Phishing",
      reason: "This page copies a trusted bank login flow.",
      riskLocation: "The scam is likely in the password form.",
      recommendedAction: "Leave the site now.",
      preventionTips: ["Type the site manually.", "Never trust urgent login links."],
      signals: [{ reason: 'Link impersonates "bank"' }],
      destinationSummary: {
        snippet: "Verify your bank account now to keep access active.",
      },
    },
  });

  const root = harness.elementsById.get("scamshield-page-warning");
  assert.match(root.innerHTML, /password form/i);
  assert.match(root.innerHTML, /Destination Preview/i);
});

test("scanner renders a suspicious page banner and opens the side panel button", () => {
  const harness = createScannerHarness();

  harness.triggerRuntimeMessage({
    type: "PAGE_SCAN_RESULT",
    analysis: {
      subjectType: "page",
      url: "https://suspicious.example.com",
      score: 42,
      verdict: "suspicious",
      scamType: "urgent phishing lure",
      aiStatus: "pending",
      headline: "Likely Urgent Phishing Lure",
      reason: "The page uses urgency language and odd login cues.",
      riskLocation: "The scam is likely in the verification prompt.",
      recommendedAction: "Avoid entering personal details.",
      preventionTips: ["Slow down before clicking.", "Check the domain manually."],
      signals: [{ reason: "Multiple urgency/fear tactics detected" }],
    },
  });

  const root = harness.elementsById.get("scamshield-page-warning");
  assert.match(root.innerHTML, /Open in Side Panel/);

  harness.elementsById.get("ss-open-panel").onclick();
  assert.equal(harness.sentMessages.at(-1)?.type, "OPEN_SIDE_PANEL");
  assert.equal(harness.document.body.style.overflow, "auto");
});

test("scanner sends ANALYZE_LINK and updates the blocked link overlay with indicators", () => {
  const harness = createScannerHarness();
  harness.triggerRuntimeMessage({
    type: "RISK_SCORES",
    riskMap: {
      "https://secure-login.fake-bank-verify.xyz/auth": 75,
    },
  });

  const anchor = {
    href: "https://secure-login.fake-bank-verify.xyz/auth",
    innerText: "Verify your bank account",
    closest(selector) {
      if (selector === "#ss-open-panel") return null;
      if (selector === "a[href]") return this;
      return null;
    },
  };

  harness.triggerClick(anchor);
  assert.equal(harness.sentMessages.at(-1)?.type, "ANALYZE_LINK");

  harness.triggerRuntimeMessage({
    type: "LINK_ANALYSIS_RESULT",
    analysis: {
      subjectType: "link",
      url: "https://secure-login.fake-bank-verify.xyz/auth",
      score: 75,
      verdict: "dangerous",
      scamType: "fake account verification link",
      aiStatus: "ready",
      headline: "Likely Fake Verification",
      reason: "The destination imitates a bank and pushes a login flow.",
      riskLocation: "The scam is likely in the fake sign-in form.",
      recommendedAction: "Do not open the destination.",
      preventionTips: ["Use the official banking app.", "Never sign in from message links."],
      signals: [
        { reason: 'Link impersonates "bank"' },
        { reason: "Suspicious TLD: xyz" },
      ],
      destinationSummary: {
        snippet: "Verify your account now to keep online access active.",
      },
    },
  });

  const overlay = harness.elementsById.get("scamshield-link-overlay");
  assert.match(overlay.innerHTML, /fake account verification link/i);
  assert.match(overlay.innerHTML, /Suspicious TLD: xyz/);
  assert.match(overlay.innerHTML, /online access active/i);
});

test("scanner dangerous overlay back button uses history.back when history exists", () => {
  const harness = createScannerHarness({ historyLength: 2 });
  harness.triggerRuntimeMessage({
    type: "RISK_SCORES",
    riskMap: {
      "https://phish.example.com": 70,
    },
  });

  const anchor = {
    href: "https://phish.example.com",
    innerText: "Open link",
    closest(selector) {
      if (selector === "#ss-open-panel") return null;
      if (selector === "a[href]") return this;
      return null;
    },
  };

  harness.triggerClick(anchor);
  harness.elementsById.get("ss-go-back").onclick();

  assert.equal(harness.historyBackCalls, 1);
  assert.equal(harness.windowCloseCalls, 0);
});

test("scanner dangerous overlay back button closes and redirects when history is missing", () => {
  const harness = createScannerHarness({ historyLength: 1 });
  harness.triggerRuntimeMessage({
    type: "RISK_SCORES",
    riskMap: {
      "https://phish.example.com": 70,
    },
  });

  const anchor = {
    href: "https://phish.example.com",
    innerText: "Open link",
    closest(selector) {
      if (selector === "#ss-open-panel") return null;
      if (selector === "a[href]") return this;
      return null;
    },
  };

  harness.triggerClick(anchor);
  harness.elementsById.get("ss-go-back").onclick();

  assert.equal(harness.historyBackCalls, 0);
  assert.equal(harness.windowCloseCalls, 1);
  assert.equal(harness.timeoutCallCount, 1);
  assert.equal(harness.locationHref, "chrome://newtab");
});

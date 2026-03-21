import test from "node:test";
import assert from "node:assert/strict";

import {
  handleAnalyzeLink,
  handleRuntimeMessage,
  handleScan,
  resetScanState,
} from "../scam-shield/background.js";

function createChromeStub() {
  const tabMessages = [];
  const storageWrites = [];
  const sidePanelOpens = [];

  return {
    chromeApi: {
      tabs: {
        sendMessage(tabId, payload) {
          tabMessages.push({ tabId, payload });
          return Promise.resolve();
        },
      },
      sidePanel: {
        open(options) {
          sidePanelOpens.push(options);
          return Promise.resolve();
        },
      },
      storage: {
        session: {
          set(payload) {
            storageWrites.push(payload);
            return Promise.resolve();
          },
        },
      },
    },
    tabMessages,
    storageWrites,
    sidePanelOpens,
  };
}

const LOW_RISK_CONTEXT = {
  url: "https://example.com",
  title: "Welcome",
  meta: { description: "Safe page" },
  links: [],
  visibleText: "Welcome to the documentation homepage.",
};

const HIGH_RISK_CONTEXT = {
  url: "https://apple-account-verify.xyz/login",
  title: "Urgent action required",
  meta: {},
  links: [
    {
      href: "https://login-check-apple.xyz/verify",
      text: "Verify account",
      isVisible: true,
      hasLoginKeyword: true,
    },
    {
      href: "https://billing-help.example.net/pay",
      text: "Payment support",
      isVisible: true,
      hasLoginKeyword: false,
    },
    {
      href: "https://security-check.example.org/confirm",
      text: "Confirm identity",
      isVisible: true,
      hasLoginKeyword: true,
    },
  ],
  visibleText:
    "Urgent security alert. Verify your account now to confirm your identity and enter your password.",
};

const HIGH_RISK_UPDATE_SAME_URL_CONTEXT = {
  ...HIGH_RISK_CONTEXT,
  url: LOW_RISK_CONTEXT.url,
};

test.beforeEach(() => {
  resetScanState();
});

test("handleScan sends immediate PAGE_SCAN_RESULT for safe pages and skips AI", async () => {
  const { chromeApi, tabMessages, storageWrites } = createChromeStub();
  let explanationCalls = 0;

  const result = await handleScan(LOW_RISK_CONTEXT, 17, {
    chromeApi,
    getExplanation: async () => {
      explanationCalls += 1;
      return null;
    },
    now: () => 1234,
  });

  assert.equal(explanationCalls, 0);
  assert.equal(tabMessages.length, 2);
  assert.equal(tabMessages[0].payload.type, "RISK_SCORES");
  assert.equal(tabMessages[1].payload.type, "PAGE_SCAN_RESULT");
  assert.equal(tabMessages[1].payload.analysis.aiStatus, "skipped");
  assert.equal(result.verdict, "safe");
  assert.equal(storageWrites.length, 1);
  assert.equal(storageWrites[0].lastScan.aiStatus, "skipped");
});

test("handleScan sends immediate and final page analysis when OpenAI succeeds", async () => {
  const { chromeApi, tabMessages, storageWrites } = createChromeStub();
  const explanation = {
    verdict: "dangerous",
    scam_type: "credential phishing",
    headline: "Likely phishing page",
    reason: "The domain impersonates Apple and uses urgency to pressure the user.",
    risk_location: "The scam is likely in the fake login form.",
    recommended_action: "Leave the site and do not enter credentials.",
    prevention_tips: [
      "Type the site manually.",
      "Check the domain before signing in.",
    ],
  };

  await handleScan(HIGH_RISK_CONTEXT, 44, {
    chromeApi,
    getExplanation: async () => explanation,
    now: () => 999999,
  });

  assert.equal(tabMessages.length, 3);
  assert.equal(tabMessages[0].payload.type, "RISK_SCORES");
  assert.equal(tabMessages[1].payload.type, "PAGE_SCAN_RESULT");
  assert.equal(tabMessages[1].payload.analysis.aiStatus, "pending");
  assert.equal(tabMessages[2].payload.type, "PAGE_EXPLANATION");
  assert.equal(tabMessages[2].payload.analysis.aiStatus, "ready");
  assert.equal(tabMessages[2].payload.analysis.scamType, "credential phishing");
  assert.equal(storageWrites.length, 2);
  assert.equal(storageWrites[0].lastScan.aiStatus, "pending");
  assert.equal(storageWrites[1].lastScan.aiStatus, "ready");
  assert.equal(storageWrites[1].lastScan.timestamp, 999999);
});

test("handleScan persists unavailable AI status without losing heuristic explanation", async () => {
  const { chromeApi, tabMessages, storageWrites } = createChromeStub();

  await handleScan(HIGH_RISK_CONTEXT, 21, {
    chromeApi,
    getExplanation: async () => null,
    now: () => 321,
  });

  assert.equal(tabMessages.length, 3);
  assert.equal(tabMessages[1].payload.type, "PAGE_SCAN_RESULT");
  assert.equal(tabMessages[2].payload.type, "PAGE_EXPLANATION");
  assert.equal(tabMessages[2].payload.analysis.aiStatus, "unavailable");
  assert.equal(tabMessages[2].payload.analysis.explanation, null);
  assert.match(tabMessages[2].payload.analysis.reason, /looks like/i);
  assert.equal(storageWrites.length, 2);
  assert.equal(storageWrites[1].lastScan.aiStatus, "unavailable");
});

test("handleScan never calls OpenAI on updates if the initial scan was below 30", async () => {
  const { chromeApi, tabMessages, storageWrites } = createChromeStub();
  let explanationCalls = 0;

  const countExplanationCall = async () => {
    explanationCalls += 1;
    return null;
  };

  await handleScan(
    LOW_RISK_CONTEXT,
    9,
    {
      chromeApi,
      getExplanation: countExplanationCall,
      now: () => 100,
    },
    "PAGE_LOADED"
  );

  await handleScan(
    HIGH_RISK_UPDATE_SAME_URL_CONTEXT,
    9,
    {
      chromeApi,
      getExplanation: countExplanationCall,
      now: () => 200,
    },
    "PAGE_UPDATED"
  );

  assert.equal(explanationCalls, 0);
  assert.equal(
    tabMessages.filter((entry) => entry.payload.type === "PAGE_SCAN_RESULT").length,
    2
  );
  assert.equal(storageWrites.length, 2);
  assert.equal(storageWrites[1].lastScan.aiStatus, "skipped");
});

test("handleScan marks aiStatus unavailable when the explanation times out", async () => {
  const { chromeApi, tabMessages, storageWrites } = createChromeStub();

  await handleScan(
    HIGH_RISK_CONTEXT,
    55,
    {
      chromeApi,
      getExplanation: () => new Promise(() => {}),
      now: () => 4040,
      explanationTimeoutMs: 5,
    },
    "PAGE_LOADED"
  );

  assert.equal(tabMessages[1].payload.type, "PAGE_SCAN_RESULT");
  assert.equal(tabMessages[2].payload.type, "PAGE_EXPLANATION");
  assert.equal(tabMessages[2].payload.analysis.aiStatus, "unavailable");
  assert.equal(storageWrites[1].lastScan.aiStatus, "unavailable");
});

test("handleAnalyzeLink sends immediate heuristic output and final enriched analysis", async () => {
  const { chromeApi, tabMessages, storageWrites } = createChromeStub();
  const explanation = {
    verdict: "dangerous",
    scam_type: "fake account verification link",
    headline: "Likely fake verification",
    reason: "The blocked link imitates a trusted service and pushes a login flow.",
    risk_location: "The scam is likely in the destination login or verification form.",
    recommended_action: "Do not open the destination.",
    prevention_tips: [
      "Open the real site manually.",
      "Avoid signing in from message links.",
    ],
  };
  const fetchCalls = [];

  await handleAnalyzeLink(
    {
      link: {
        href: "https://secure-login.fake-bank-verify.xyz/auth",
        text: "Verify your bank account",
      },
      pageContext: {
        url: "https://mail.example.com",
        title: "Inbox",
        visibleText: "Verify your bank account immediately to prevent suspension.",
      },
    },
    88,
    {
      chromeApi,
      fetchImpl: async (url, options) => {
        fetchCalls.push({ url, options });
        return {
          ok: true,
          headers: {
            get() {
              return "text/html";
            },
          },
          async text() {
            return `
              <html>
                <head>
                  <title>Account Verification</title>
                  <meta name="description" content="Verify your bank account now" />
                </head>
                <body>Verify your account now to keep online access active.</body>
              </html>
            `;
          },
        };
      },
      getExplanation: async () => explanation,
      now: () => 999,
      destinationTimeoutMs: 50,
    }
  );

  assert.equal(tabMessages.length, 2);
  assert.equal(tabMessages[0].payload.type, "LINK_ANALYSIS_RESULT");
  assert.equal(tabMessages[0].payload.analysis.aiStatus, "pending");
  assert.equal(tabMessages[1].payload.analysis.aiStatus, "ready");
  assert.match(tabMessages[1].payload.analysis.destinationSummary.snippet, /Verify your account now/);
  assert.equal(storageWrites.length, 2);
  assert.equal(fetchCalls[0].options.headers["User-Agent"], "Mozilla/5.0");
});

test("handleAnalyzeLink falls back from CORS failure to no-cors and skips unreadable destination summary", async () => {
  const { chromeApi, tabMessages, storageWrites } = createChromeStub();
  const fetchCalls = [];

  await handleAnalyzeLink(
    {
      link: {
        href: "https://secure-login.fake-bank-verify.xyz/auth",
        text: "Verify your bank account",
      },
      pageContext: {
        url: "https://mail.example.com",
        title: "Inbox",
        visibleText: "Verify your bank account immediately.",
      },
    },
    66,
    {
      chromeApi,
      fetchImpl: async (url, options = {}) => {
        fetchCalls.push({ url, options });
        if (!options.mode) {
          const error = new TypeError("CORS blocked");
          throw error;
        }
        return { type: "opaque" };
      },
      getExplanation: async () => null,
      destinationTimeoutMs: 50,
      explanationTimeoutMs: 50,
      now: () => 1010,
    }
  );

  assert.equal(fetchCalls.length, 2);
  assert.equal(fetchCalls[1].options.mode, "no-cors");
  assert.equal(tabMessages.length, 2);
  assert.equal(tabMessages[0].payload.analysis.aiStatus, "pending");
  assert.equal(tabMessages[1].payload.analysis.aiStatus, "unavailable");
  assert.equal(tabMessages[1].payload.analysis.destinationSummary, null);
  assert.equal(storageWrites[1].lastLinkAnalysis.destinationSummary, null);
});

test("handleRuntimeMessage opens the side panel for OPEN_SIDE_PANEL", async () => {
  const { chromeApi, sidePanelOpens } = createChromeStub();

  await handleRuntimeMessage(
    { type: "OPEN_SIDE_PANEL" },
    { tab: { id: 77 } },
    { chromeApi }
  );

  assert.deepEqual(sidePanelOpens, [{ tabId: 77 }]);
});

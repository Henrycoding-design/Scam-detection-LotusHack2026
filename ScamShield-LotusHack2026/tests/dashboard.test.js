import test from "node:test";
import assert from "node:assert/strict";

import {
  buildAnalysisCard,
  renderDashboard,
} from "../scam-shield/dashboard/dashboard.js";

const SAMPLE_ANALYSIS = {
  url: "https://secure-login.fake-bank-verify.xyz/auth",
  score: 75,
  verdict: "dangerous",
  aiStatus: "ready",
  scamType: "fake account verification link",
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
};

test("buildAnalysisCard includes the main explanation sections", () => {
  const markup = buildAnalysisCard("Last Blocked Link", SAMPLE_ANALYSIS);

  assert.match(markup, /Likely Scam Type/);
  assert.match(markup, /fake account verification link/i);
  assert.match(markup, /Most Notable Signals/);
  assert.match(markup, /How To Avoid Scams Like This/);
  assert.match(markup, /Destination Preview/);
});

test("renderDashboard renders both page and link analysis cards", () => {
  const root = { innerHTML: "" };

  renderDashboard(root, {
    lastScan: SAMPLE_ANALYSIS,
    lastLinkAnalysis: SAMPLE_ANALYSIS,
  });

  assert.match(root.innerHTML, /Current Page/);
  assert.match(root.innerHTML, /Last Blocked Link/);
});

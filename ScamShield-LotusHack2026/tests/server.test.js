import test from "node:test";
import assert from "node:assert/strict";

import { analyzeScan } from "../server.ts";

test("analyzeScan returns normalized analysis with OpenAI explanation data", async () => {
  const response = await analyzeScan(
    {
      url: "https://apple-security-check.xyz/login",
      links: [],
      text: "Urgent action required to keep your account active.",
    },
    {
    runScoring: () => ({
      score: 82,
      verdict: "dangerous",
      reasons: ["Domain impersonates a trusted brand"],
      signals: [
        { type: "brand_impersonation_page", weight: 40, reason: 'Domain impersonates "apple"' },
        { type: "urgency_language", weight: 30, reason: "Multiple urgency/fear tactics detected" },
      ],
    }),
    saveScan: async () => "mock-id",
    getExplanation: async () => ({
      verdict: "dangerous",
      scam_type: "credential phishing",
      headline: "Likely phishing page",
      reason: "This page imitates a trusted login flow and pressures the user.",
      risk_location: "The scam is likely in the fake sign-in form.",
      recommended_action: "Leave the site and do not enter credentials.",
      prevention_tips: [
        "Type the official site manually.",
        "Check the domain before signing in.",
      ],
    }),
    }
  );

  assert.equal(response.risk, 82);
  assert.equal(response.verdict, "dangerous");
  assert.equal(response.analysis.aiStatus, "ready");
  assert.equal(response.analysis.scamType, "credential phishing");
  assert.match(response.analysis.reason, /trusted login flow/i);
});

test("analyzeScan preserves heuristics when OpenAI is unavailable", async () => {
  let saveCalls = 0;
  const response = await analyzeScan(
    {
      url: "https://example-login-check.biz",
      links: [],
      text: "Please verify your password to avoid losing access.",
    },
    {
    runScoring: () => ({
      score: 45,
      verdict: "suspicious",
      reasons: ["Login pattern on unrecognized domain"],
      signals: [
        { type: "sensitive_data_request", weight: 30, reason: "Page requests sensitive information" },
        { type: "urgency_language_mild", weight: 15, reason: "Mild urgency language detected" },
      ],
    }),
    saveScan: async () => {
      saveCalls += 1;
      return "mock-id";
    },
    getExplanation: async () => null,
    }
  );

  assert.equal(response.explanation, null);
  assert.equal(response.analysis.aiStatus, "unavailable");
  assert.equal(response.analysis.verdict, "suspicious");
  assert.match(response.analysis.reason, /looks like/i);
  assert.equal(saveCalls, 1);
});

import test from "node:test";
import assert from "node:assert/strict";

import {
  scorePageContext,
  scoreSingleLink,
} from "../scam-shield/scoring/heuristics.js";

test("scorePageContext identifies a high-risk scam page", () => {
  const context = {
    url: "https://apple-account-verify.xyz/login",
    title: "Urgent action required",
    meta: {},
    links: [
      {
        href: "https://verify-apple-login.xyz",
        text: "Verify login",
        isVisible: true,
        hasLoginKeyword: true,
      },
      {
        href: "https://billing-review.example.org",
        text: "Billing review",
        isVisible: true,
        hasLoginKeyword: false,
      },
      {
        href: "https://security-check.example.net",
        text: "Security check",
        isVisible: true,
        hasLoginKeyword: true,
      },
    ],
    visibleText:
      "Urgent security alert. Verify your account now. Confirm your identity and enter your password immediately.",
  };

  const result = scorePageContext(context);

  assert.ok(result.score >= 70);
  assert.ok(result.signals.some((signal) => signal.type === "brand_impersonation_page"));
  assert.ok(result.signals.some((signal) => signal.type === "urgency_language"));
  assert.ok(result.signals.some((signal) => signal.type === "sensitive_data_request"));
});

test("scorePageContext keeps an ordinary informational page below the LLM threshold", () => {
  const context = {
    url: "https://example.com",
    title: "Example Domain",
    meta: {
      description: "Illustrative examples for documents.",
      "og:description": "Illustrative examples for documents.",
    },
    links: [
      {
        href: "https://www.iana.org/domains/example",
        text: "More information",
        isVisible: true,
        hasLoginKeyword: false,
      },
    ],
    visibleText: "This domain is for use in documentation examples without any login prompt.",
  };

  const result = scorePageContext(context);

  assert.ok(result.score < 30);
  assert.equal(result.signals.length, 0);
});

test("scoreSingleLink flags a shortener and branded off-site login destination", () => {
  const result = scoreSingleLink("https://paypal.bit.ly/verify", "mail.example.com");

  assert.ok(result.score >= 35);
  assert.ok(result.signals.some((signal) => signal.type === "url_shortener"));
  assert.ok(result.signals.some((signal) => signal.type === "brand_impersonation_link"));
});

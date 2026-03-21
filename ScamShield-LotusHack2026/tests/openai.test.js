import test from "node:test";
import assert from "node:assert/strict";

import {
  buildOpenAIExplanationRequest,
  getOpenAIExplanation,
} from "../scam-shield/scoring/openai.js";

const SAMPLE_CONTEXT = {
  url: "https://apple-secure-login.xyz/reset",
  score: 82,
  subjectType: "link",
  likelyScamType: "fake account verification link",
  signals: [
    { type: "brand_impersonation_page", weight: 40, reason: 'Domain impersonates "apple"' },
    { type: "urgency_language", weight: 30, reason: "Multiple urgency/fear tactics detected" },
    { type: "suspicious_tld", weight: 20, reason: "Suspicious TLD: xyz" },
    { type: "no_meta_description", weight: 8, reason: "Page has no description meta tag (thin content)" },
  ],
  visibleText: "A".repeat(650),
  destinationSummary: {
    title: "Account Verification",
    description: "Verify your account immediately",
    snippet: "Confirm your identity and enter your password to avoid account suspension.",
  },
};

test("buildOpenAIExplanationRequest uses the expected model, schema, and destination context", () => {
  const requestBody = buildOpenAIExplanationRequest(SAMPLE_CONTEXT);

  assert.equal(requestBody.model, "gpt-5.4");
  assert.equal(requestBody.store, false);
  assert.deepEqual(requestBody.reasoning, { effort: "low" });
  assert.equal(requestBody.text.format.type, "json_schema");
  assert.equal(requestBody.text.format.strict, true);
  assert.deepEqual(requestBody.text.format.schema.required, [
    "verdict",
    "scam_type",
    "headline",
    "reason",
    "risk_location",
    "recommended_action",
    "prevention_tips",
  ]);

  assert.match(requestBody.input, /Subject Type: link/);
  assert.match(requestBody.input, /fake account verification link/);
  assert.match(requestBody.input, /Domain impersonates "apple"/);
  assert.match(requestBody.input, /Title: Account Verification/);
  assert.match(requestBody.input, /Description: Verify your account immediately/);
  assert.doesNotMatch(requestBody.input, /Page has no description meta tag/);

  const promptText = requestBody.input.split('Page text snippet:\n"')[1];
  const snippet = promptText.split('"')[0];
  assert.equal(snippet.length, 600);
});

test("buildOpenAIExplanationRequest omits destination summary when it is unavailable", () => {
  const requestBody = buildOpenAIExplanationRequest({
    ...SAMPLE_CONTEXT,
    destinationSummary: null,
  });

  assert.match(requestBody.input, /Unavailable or unreadable/);
});

test("getOpenAIExplanation sends a Responses API request and parses a valid response body", async () => {
  let fetchCall = null;
  const explanation = {
    verdict: "dangerous",
    scam_type: "credential phishing",
    headline: "Likely phishing page",
    reason: "This page imitates a trusted brand and pressures the user to act quickly.",
    risk_location: "The scam is likely in the fake login flow and domain branding.",
    recommended_action: "Leave the site and do not enter credentials.",
    prevention_tips: [
      "Type the official site manually.",
      "Check the domain before signing in.",
    ],
  };

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    fetchCall = { url, options };
    return {
      ok: true,
      async json() {
        return {
          output: [
            {
              content: [
                {
                  type: "output_text",
                  text: JSON.stringify(explanation),
                },
              ],
            },
          ],
        };
      },
    };
  };

  try {
    const result = await getOpenAIExplanation(SAMPLE_CONTEXT);
    assert.deepEqual(result, explanation);
    assert.equal(fetchCall.url, "https://api.openai.com/v1/responses");
    assert.equal(fetchCall.options.method, "POST");
    assert.match(fetchCall.options.headers.Authorization, /^Bearer\s+\S+$/);

    const body = JSON.parse(fetchCall.options.body);
    assert.equal(body.model, "gpt-5.4");
    assert.equal(body.text.format.name, "scamshield_explanation");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("getOpenAIExplanation returns null for non-OK responses", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: false,
    status: 401,
    async json() {
      return {};
    },
  });

  try {
    const result = await getOpenAIExplanation(SAMPLE_CONTEXT);
    assert.equal(result, null);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("getOpenAIExplanation returns null for invalid JSON text", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    async json() {
      return {
        output: [
          {
            content: [
              {
                type: "output_text",
                text: "```json\nnot valid json\n```",
              },
            ],
          },
        ],
      };
    },
  });

  try {
    const result = await getOpenAIExplanation(SAMPLE_CONTEXT);
    assert.equal(result, null);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("getOpenAIExplanation returns null for schema mismatches", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    async json() {
      return {
        output: [
          {
            content: [
              {
                parsed: {
                  verdict: "dangerous",
                  headline: "Missing fields example",
                },
              },
            ],
          },
        ],
      };
    },
  });

  try {
    const result = await getOpenAIExplanation(SAMPLE_CONTEXT);
    assert.equal(result, null);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# ScamShield

ScamShield is a Chrome extension prototype for real-time scam detection. It combines fast heuristic scoring with an OpenAI Responses API explanation layer for demo/debugging.

## Important Demo Note

The OpenAI integration is intentionally hard-coded in [`scam-shield/scoring/openai.js`](scam-shield/scoring/openai.js) for debugging right now.

- It uses `gpt-5.4` via `POST /v1/responses`
- The API key is stored directly in the extension source for demo purposes
- This is not safe for production and should move to a backend before any real deployment

## Extension Setup

1. Open Chrome and go to `chrome://extensions`
2. Enable Developer Mode
3. Click Load unpacked
4. Select the [`scam-shield`](scam-shield) folder

## Local Development

1. Install dependencies:
   `npm install`
2. Run the app shell if you want the Vite scaffold locally:
   `npm run dev`
3. Run automated checks available in this repo:
   `npm test`

## Demo Pages

Use [`scam-patterns/index.html`](scam-patterns/index.html) as a simple local page for scam-pattern testing.

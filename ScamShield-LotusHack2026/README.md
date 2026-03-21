<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# ScamShield LotusHack'26

This merged project combines:
- the OpenAI-based Chrome extension and structured page/link explanation flow
- the Gemini website shell and Express backend
- a single OpenAI analysis path for both the extension and the website backend

## Run Locally

**Prerequisites:** Node.js

1. Install dependencies:
   `npm install`
2. Copy `.env.example` to `.env` and set:
   `OPENAI_API_KEY`, `SUPABASE_URL`, and `SUPABASE_ANON_KEY`
3. Run the website and backend:
   `npm run dev`
4. Run automated tests:
   `npm test`

## Chrome Extension

1. Open Chrome and go to `chrome://extensions`
2. Enable Developer Mode
3. Click Load unpacked
4. Select the `scam-shield` folder

## Notes

- The website UI is inherited from the Gemini project.
- The extension implementation and tests are inherited from the OpenAI project.
- The extension's `scam-shield/scoring/openai.js` file still contains the original demo-only hard-coded key path from the source repo and should be moved behind the backend before any real deployment.

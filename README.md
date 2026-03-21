# ScamShield Extension MVP

Chrome extension MVP for hackathon phishing and scam detection.

## What It Does

- Scans the current page for suspicious URL, text, metadata, and link signals
- Scores the page locally inside the extension
- Calls Gemini or OpenRouter directly from the extension for a user-facing explanation and validation
- Shows the result in the side panel and warns on risky links

## Run It

1. Open `chrome://extensions`
2. Turn on `Developer mode`
3. Click `Load unpacked`
4. Select the [scam-shield](./scam-shield) folder
5. Optional for local dev: create `scam-shield/config.local.json` from `scam-shield/config.local.example.json`
6. Open the extension details page and click `Extension options`
7. Choose `Auto`, `Gemini`, or `OpenRouter`, then save your keys/models
8. Open any page and click the extension icon to view the side panel

## AI Provider Setup

- Settings saved in `chrome.storage.local` take priority.
- If storage is empty, ScamShield falls back to `scam-shield/config.local.json`.
- `Auto` tries Gemini first when configured, then OpenRouter.
- The root repository `.env` file is not read by the unpacked extension.

## Hackathon Note

This MVP calls external AI providers directly from the extension for speed of development.
That is acceptable for a hackathon demo, but not secure for production.

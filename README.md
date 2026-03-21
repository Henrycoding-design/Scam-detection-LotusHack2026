# ScamShield Extension MVP

Chrome extension MVP for hackathon phishing and scam detection.

## What It Does

- Scans the current page for suspicious URL, text, metadata, and link signals
- Scores the page locally inside the extension
- Calls Gemini directly from the extension for a short user-facing explanation
- Shows the result in the side panel and warns on risky links

## Run It

1. Open `chrome://extensions`
2. Turn on `Developer mode`
3. Click `Load unpacked`
4. Select the [scam-shield](./scam-shield) folder
5. Open any page and click the extension icon to view the side panel

## Hackathon Note

This MVP calls Gemini directly from the extension for speed of development.
That is acceptable for a hackathon demo, but not secure for production.

<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# ScamShield Extension

Real-time scam detection for every page you visit.

## Development

**Prerequisites:** Node.js

1. Install dependencies:
   ```
   npm install
   ```
2. Configure API keys in `scam-shield/background.js`:
   - Replace `BUILTIN_GSB_KEY_PLACEHOLDER` with your Google Safe Browsing API key
   - Replace `BUILTIN_VT_KEY_PLACEHOLDER` with your VirusTotal API key
   - Replace `BUILTIN_OPENROUTER_KEY_PLACEHOLDER` with your OpenRouter API key
3. Build the dashboard:
   ```
   npm run build
   ```
4. Load the extension in Chrome:
   - Open `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked" and select the `scam-shield` folder
5. Open the side panel (click extension icon → side panel opens) to view the dashboard.

## Features

- Scans all links, buttons, downloads, forms, iframes, and media in real-time
- Uses mutation observer for event-driven detection (no polling)
- Concurrent scanning with batching and IndexedDB storage
- Google Safe Browsing + VirusTotal integration
- AI-powered explanations via OpenRouter (stepfun/step-3.5-flash:free)
- Blocking UI with popup warnings and "Visit Anyway" override
- Dashboard with live statistics and element list
- Push-based updates via chrome.runtime.Port

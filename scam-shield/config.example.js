// config.example.js — copy to config.js and fill in your API keys
// This file is loaded via importScripts into the service worker.
// DO NOT use const/let/var — background.js already declares API_KEYS.
API_KEYS = {
  GOOGLE_SAFE_BROWSING: "YOUR_GSB_KEY_HERE",
  VIRUSTOTAL: "YOUR_VT_KEY_HERE",
  OPENROUTER: "YOUR_OPENROUTER_KEY_HERE",
  OPENAI: "YOUR_OPENAI_KEY_HERE",
};

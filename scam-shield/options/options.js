const providerInput = document.getElementById("ai-provider");
const geminiApiKeyInput = document.getElementById("gemini-api-key");
const geminiModelInput = document.getElementById("gemini-model");
const openrouterApiKeyInput = document.getElementById("openrouter-api-key");
const openrouterModelInput = document.getElementById("openrouter-model");
const saveButton = document.getElementById("save-settings");
const statusEl = document.getElementById("status");

async function loadLocalConfig() {
  try {
    const response = await fetch(chrome.runtime.getURL("config.local.json"), {
      cache: "no-store",
    });
    if (!response.ok) return {};
    return await response.json();
  } catch {
    return {};
  }
}

async function restoreSettings() {
  const stored = await chrome.storage.local.get([
    "aiProvider",
    "geminiApiKey",
    "geminiModel",
    "openrouterApiKey",
    "openrouterModel",
  ]);
  const local = await loadLocalConfig();

  providerInput.value = stored.aiProvider || local.aiProvider || "auto";
  geminiApiKeyInput.value = stored.geminiApiKey || local.geminiApiKey || "";
  geminiModelInput.value = stored.geminiModel || local.geminiModel || "gemini-2.5-flash";
  openrouterApiKeyInput.value = stored.openrouterApiKey || local.openrouterApiKey || "";
  openrouterModelInput.value = stored.openrouterModel || local.openrouterModel || "stepfun/step-3.5-flash:free";

  if (!stored.aiProvider && Object.keys(local).length > 0) {
    statusEl.textContent = "Using fallback values from config.local.json until you save overrides here.";
  }
}

async function saveSettings() {
  await chrome.storage.local.set({
    aiProvider: providerInput.value,
    geminiApiKey: geminiApiKeyInput.value.trim(),
    geminiModel: geminiModelInput.value.trim() || "gemini-2.5-flash",
    openrouterApiKey: openrouterApiKeyInput.value.trim(),
    openrouterModel: openrouterModelInput.value.trim() || "stepfun/step-3.5-flash:free",
  });

  statusEl.textContent = "Settings saved. Reload the extension or rescan a page to use the new provider configuration.";
}

saveButton.addEventListener("click", () => {
  saveSettings().catch((error) => {
    statusEl.textContent = `Failed to save settings: ${error.message || error}`;
  });
});

restoreSettings().catch((error) => {
  statusEl.textContent = `Failed to load settings: ${error.message || error}`;
});

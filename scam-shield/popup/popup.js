const statusLabel = document.getElementById("scan-status");
const openDashboardButton = document.getElementById("open-dashboard");

async function hydratePopup() {
  try {
    const [activeTab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    if (activeTab?.url) {
      const hostname = new URL(activeTab.url).hostname;
      statusLabel.textContent = `Monitoring ${hostname}`;
    }
  } catch (error) {
    statusLabel.textContent = "Monitoring this tab";
  }
}

openDashboardButton?.addEventListener("click", async () => {
  try {
    const [activeTab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    if (typeof activeTab?.windowId === "number") {
      await chrome.sidePanel.open({ windowId: activeTab.windowId });
      window.close();
    }
  } catch (error) {
    console.error("[ScamShield] Failed to open side panel:", error);
  }
});

hydratePopup();

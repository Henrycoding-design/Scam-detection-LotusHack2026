// Chrome runtime messaging wrapper with TypeScript types

// Connect to background and initialize dashboard subscription
export function connectToBackground(tabId: number) {
  const port = chrome.runtime.connect({ name: 'dashboard' });
  port.postMessage({ type: 'INIT_DASHBOARD', tabId });

  return {
    port,
    onMessage(callback: (message: any) => void) {
      port.onMessage.addListener(callback);
    },
    disconnect() {
      port.disconnect();
    }
  };
}

// Get active tab ID from the side panel context
export async function getActiveTabId(): Promise<number> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tabs.length === 0) throw new Error('No active tab');
  return tabs[0].id!;
}



export async function setActiveTabId(tabId) {
  await chrome.storage.session.set({ activeTabId: tabId });
}

export async function setTabResult(tabId, result) {
  await chrome.storage.session.set({ [`scanResult_${tabId}`]: result });
}

export async function getTabResult(tabId) {
  const key = `scanResult_${tabId}`;
  const { [key]: result } = await chrome.storage.session.get(key);
  return result || null;
}

export async function removeTabResult(tabId) {
  await chrome.storage.session.remove(`scanResult_${tabId}`);
}

export async function updateSidebar(tabId, result, status) {
  const patch = { scanStatus: status, activeTabId: tabId };
  if (result) patch.lastPageResult = result;
  await chrome.storage.session.set(patch);
}

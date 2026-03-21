export async function setScanState(patch) {
  await chrome.storage.session.set(patch);
}

export async function getScanState(keys) {
  return chrome.storage.session.get(keys);
}

export async function setScanStatus(scanStatus) {
  await chrome.storage.session.set({ scanStatus });
}

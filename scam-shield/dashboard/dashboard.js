export function buildAnalysisCard(title, analysis) {
  if (!analysis) {
    return `
      <section class="card">
        <h2 style="margin:0 0 8px; font-size:1.05rem;">${escapeHtml(title)}</h2>
        <p style="margin:0;">No analysis available yet.</p>
      </section>
    `;
  }

  const signalItems = (analysis.signals || [])
    .map((signal) => `<li>${escapeHtml(signal.reason)}</li>`)
    .join("");
  const preventionItems = (analysis.preventionTips || [])
    .map((tip) => `<li>${escapeHtml(tip)}</li>`)
    .join("");
  const verdictColor =
    analysis.verdict === "dangerous"
      ? "#ff5867"
      : analysis.verdict === "suspicious"
        ? "#f3b45c"
        : "#6ed79a";

  return `
    <section class="card">
      <div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start;">
        <div>
          <h2 style="margin:0 0 6px; font-size:1.05rem;">${escapeHtml(title)}</h2>
          <div style="font-size:0.86rem; color:${verdictColor}; font-weight:700;">
            ${escapeHtml(String(analysis.verdict || "").toUpperCase())} • ${analysis.score}/100
          </div>
        </div>
        <div style="font-size:0.82rem; color:#b7b8c9;">${escapeHtml(analysis.aiStatus || "unknown")}</div>
      </div>
      <p style="margin:10px 0 14px; color:#b7b8c9; word-break:break-all;">${escapeHtml(analysis.url)}</p>
      <div style="display:grid; gap:12px;">
        <section>
          <div style="font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em; opacity:0.7;">Likely Scam Type</div>
          <div style="font-weight:700; margin-top:4px;">${escapeHtml(analysis.scamType)}</div>
        </section>
        <section>
          <div style="font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em; opacity:0.7;">Headline</div>
          <div style="margin-top:4px;">${escapeHtml(analysis.headline)}</div>
        </section>
        <section>
          <div style="font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em; opacity:0.7;">Why It Was Flagged</div>
          <p style="margin:4px 0 0;">${escapeHtml(analysis.reason)}</p>
        </section>
        <section>
          <div style="font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em; opacity:0.7;">Most Notable Signals</div>
          <ul style="margin:6px 0 0; padding-left:18px;">${signalItems || "<li>No heuristic signals recorded.</li>"}</ul>
        </section>
        <section>
          <div style="font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em; opacity:0.7;">Where The Scam Likely Is</div>
          <p style="margin:4px 0 0;">${escapeHtml(analysis.riskLocation)}</p>
        </section>
        ${
          analysis.destinationSummary?.snippet
            ? `<section>
                <div style="font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em; opacity:0.7;">Destination Preview</div>
                <p style="margin:4px 0 0;">${escapeHtml(analysis.destinationSummary.snippet)}</p>
              </section>`
            : ""
        }
        <section>
          <div style="font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em; opacity:0.7;">How To Avoid Scams Like This</div>
          <ul style="margin:6px 0 0; padding-left:18px;">${preventionItems || "<li>No prevention tips available.</li>"}</ul>
        </section>
        <section>
          <div style="font-size:0.78rem; text-transform:uppercase; letter-spacing:0.08em; opacity:0.7;">What To Do Right Now</div>
          <p style="margin:4px 0 0;">${escapeHtml(analysis.recommendedAction)}</p>
        </section>
      </div>
    </section>
  `;
}

export function renderDashboard(root, state) {
  root.innerHTML = [
    buildAnalysisCard("Current Page", state.lastScan),
    buildAnalysisCard("Last Blocked Link", state.lastLinkAnalysis),
  ].join("");
}

export async function initDashboard(
  chromeApi = globalThis.chrome,
  documentRef = globalThis.document
) {
  const root = documentRef.getElementById("dashboard-root");
  if (!root || !chromeApi?.storage?.session) {
    return;
  }

  const currentState = await chromeApi.storage.session.get([
    "lastScan",
    "lastLinkAnalysis",
  ]);
  renderDashboard(root, currentState);

  chromeApi.storage?.onChanged?.addListener((changes, areaName) => {
    if (areaName !== "session") {
      return;
    }

    currentState.lastScan = changes.lastScan?.newValue ?? currentState.lastScan;
    currentState.lastLinkAnalysis =
      changes.lastLinkAnalysis?.newValue ?? currentState.lastLinkAnalysis;

    renderDashboard(root, {
      lastScan: currentState.lastScan,
      lastLinkAnalysis: currentState.lastLinkAnalysis,
    });
  });
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

if (globalThis.document && globalThis.chrome) {
  initDashboard().catch((error) => {
    console.warn("[ScamShield] Dashboard init failed:", error);
  });
}

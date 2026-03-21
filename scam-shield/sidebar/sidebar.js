const VERDICT_THEME = {
  safe: { color: "#22c55e", bg: "#052e16", label: "Safe" },
  suspicious: { color: "#f59e0b", bg: "#1c1100", label: "Suspicious" },
  dangerous: { color: "#ef4444", bg: "#1c0000", label: "Dangerous" },
  scanning: { color: "#94a3b8", bg: "#111827", label: "Scanning" },
  not_scannable: { color: "#64748b", bg: "#111827", label: "Not Scannable" },
};

const app = document.getElementById("app");

function escapeHtml(value = "") {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function render(state) {
  const scan = state.lastPageResult || null;
  const status = state.scanStatus || "scanning";
  const verdict = status === "scanning" ? "scanning" : (scan?.verdict || "safe");
  const theme = VERDICT_THEME[verdict] || VERDICT_THEME.scanning;
  const reasons = (scan?.reasons || []).slice(0, 3);
  const aiLoading = status === "heuristic_ready" && (!scan?.explanation || scan?.aiStatus === "loading");

  if (!scan && status !== "scanning") {
    app.innerHTML = `
      <div class="header">
        <span>🛡️</span>
        <span class="brand">ScamShield</span>
      </div>
      <div class="empty">Navigate to a page to begin scanning.</div>
    `;
    return;
  }

  app.innerHTML = `
    <div class="header">
      <span>🛡️</span>
      <span class="brand">ScamShield</span>
    </div>

    <div class="card" style="background:${theme.bg}; border-color:${theme.color};">
      <div class="pill" style="color:${theme.color};">${theme.label}</div>
      <div class="score" style="color:${theme.color};">${scan?.score ?? "--"}/100</div>
      <div class="muted">${status === "scanning" ? "Scanning page..." : "Latest page result"}</div>
      <div class="bar">
        <div class="bar-fill" style="width:${scan?.score ?? 0}%; background:${theme.color};"></div>
      </div>
    </div>

    ${reasons.length ? `
      <div class="card">
        <div class="pill muted">Top Reasons</div>
        ${reasons.map((r) => {
          const text = typeof r === "string" ? r : r.reason;
          const detail = typeof r === "string" ? "" : (r.detail || "");
          if (detail) {
            return `<div class="reason-expandable" onclick="this.classList.toggle('expanded')">
              <div class="reason-header">${escapeHtml(text)}</div>
              <div class="reason-detail">${escapeHtml(detail)}</div>
            </div>`;
          }
          return `<div class="reason">${escapeHtml(text)}</div>`;
        }).join("")}
      </div>
    ` : ""}

    <div class="card">
      <div class="pill muted">AI Analysis</div>
      ${aiLoading ? `
        <div class="loading">Generating explanation...</div>
      ` : scan?.explanation ? `
        <div style="font-weight:700; margin-bottom:6px;">${escapeHtml(scan.explanation.headline || "")}</div>
        <div style="font-size:13px; color:#d1d5db; margin-bottom:8px;">${escapeHtml(scan.explanation.reason || "")}</div>
        <div class="muted">${escapeHtml(scan.explanation.recommended_action || "")}</div>
      ` : `
        <div class="muted">No AI explanation for this page.</div>
      `}
    </div>

    ${scan?.url ? `
      <div class="card">
        <div class="pill muted">Page URL</div>
        <div class="muted" style="word-break:break-all;">${escapeHtml(scan.url)}</div>
      </div>
    ` : ""}
  `;
}

async function refresh() {
  const state = await chrome.storage.session.get(["lastPageResult", "scanStatus"]);
  render(state);
}

// Background writes to lastPageResult/scanStatus on both scan completion and tab switch,
// so this single listener handles both cases.
chrome.storage.session.onChanged.addListener(refresh);

refresh();

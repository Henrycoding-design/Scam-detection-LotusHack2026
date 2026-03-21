const VERDICT_THEME = {
  safe: { color: "#22c55e", bg: "#052e16", label: "Safe" },
  suspicious: { color: "#f59e0b", bg: "#1c1100", label: "Suspicious" },
  dangerous: { color: "#ef4444", bg: "#1c0000", label: "Dangerous" },
  scanning: { color: "#94a3b8", bg: "#111827", label: "Scanning" },
  not_scannable: { color: "#64748b", bg: "#111827", label: "Not Scannable" },
};

const app = document.getElementById("app");
const logo = `<img src="${chrome.runtime.getURL("icon.png")}" class="logo" alt="ScamShield">`;

function escapeHtml(value = "") {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function formatInlineMarkdown(value = "") {
  return escapeHtml(value).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
}

function getRecommendedActions(explanation) {
  if (Array.isArray(explanation?.recommended_actions) && explanation.recommended_actions.length > 0) {
    return explanation.recommended_actions;
  }

  if (explanation?.recommended_action) {
    return [{
      title: "Recommended next step",
      detail: explanation.recommended_action,
    }];
  }

  return [];
}

function render(state) {
  const scan = state.lastPageResult || null;
  const status = state.scanStatus || "scanning";
  const verdict = status === "scanning" ? "scanning" : (scan?.verdict || "safe");
  const theme = VERDICT_THEME[verdict] || VERDICT_THEME.scanning;
  const reasons = (scan?.reasons || []).slice(0, 3);
  const aiLoading = status === "heuristic_ready" && (!scan?.explanation || scan?.aiStatus === "loading");
  const recommendedActions = getRecommendedActions(scan?.explanation);

  if (!scan && status !== "scanning") {
    app.innerHTML = `
      <div class="header">
        ${logo}
        <div>
          <div class="brand">ScamShield</div>
          <h1 class="page-title">Sidebar Analysis</h1>
        </div>
      </div>
      <div class="empty">Navigate to a page to begin scanning.</div>
    `;
    return;
  }

  app.innerHTML = `
    <div class="header">
      ${logo}
      <div>
        <div class="brand">ScamShield</div>
        <h1 class="page-title">Sidebar Analysis</h1>
      </div>
    </div>

    <div class="card" style="background:${theme.bg}; border-color:${theme.color};">
      <div class="pill" style="color:${theme.color};">${theme.label}</div>
      <div class="score" style="color:${theme.color};">${scan?.score ?? "--"}% safe</div>
      <div class="muted">${status === "scanning" ? "Scanning page..." : "Safety score"}</div>
      <div class="bar">
        <div class="bar-fill" style="width:${scan?.score ?? 0}%; background:${theme.color};"></div>
      </div>
    </div>

    ${scan?.explanation ? `
      <div class="card overview">
        <h2 class="section-title">Overview</h2>
        <div class="overview-highlight">
          <div class="overview-headline formatted">${formatInlineMarkdown(scan.explanation.headline || "AI overview")}</div>
          <div class="muted">This is a summary of the overall pattern the model noticed. It should be read as guidance, not certainty.</div>
        </div>
      </div>
    ` : ""}

    ${recommendedActions.length ? `
      <div class="card">
        <h2 class="section-title">Recommended Actions</h2>
        <div class="action-list">
          ${recommendedActions.map((action) => `
            <div class="reason-expandable action-card">
              <div class="reason-header"><strong>${escapeHtml(action.title || "Recommended step")}</strong></div>
              <div class="reason-detail formatted">${formatInlineMarkdown(action.detail || "")}</div>
            </div>
          `).join("")}
        </div>
      </div>
    ` : ""}

    ${reasons.length ? `
      <div class="card">
        <h2 class="section-title">Top Reasons</h2>
        ${reasons.map((r) => {
          const detail = r.detail || "";
          if (detail) {
            return `<div class="reason-expandable">
              <div class="reason-header">${escapeHtml(r.reason)}</div>
              <div class="reason-detail">${escapeHtml(detail)}</div>
            </div>`;
          }
          return `<div class="reason">${escapeHtml(r.reason)}</div>`;
        }).join("")}
      </div>
    ` : ""}

    <div class="card">
      <h2 class="section-title">AI Analysis</h2>
      ${aiLoading ? `
        <div class="loading">Generating explanation...</div>
      ` : scan?.explanation ? `
        <h3 class="subsection-title">Pattern Explanation</h3>
        <div class="analysis-body formatted">${formatInlineMarkdown(scan.explanation.reason || "")}</div>
      ` : `
        <div class="muted">No AI explanation for this page.</div>
      `}
    </div>

    ${scan?.url ? `
      <div class="card">
        <h2 class="section-title">Page URL</h2>
        <div class="muted" style="word-break:break-all;">${escapeHtml(scan.url)}</div>
      </div>
    ` : ""}
  `;

  app.querySelectorAll(".reason-expandable").forEach((el) => {
    el.addEventListener("click", () => {
      el.classList.toggle("expanded");
    });
  });
}

async function refresh() {
  const state = await chrome.storage.session.get(["lastPageResult", "scanStatus"]);
  render(state);
}

chrome.storage.session.onChanged.addListener(refresh);

refresh();

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
  const explanation = scan?.explanation || null;
  const aiLoading = status === "heuristic_ready" && (!explanation || scan?.aiStatus === "loading");

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

  // Build reasons list — first item gets the AI explanation if available
  let reasonsHtml = "";
  if (reasons.length > 0 || explanation) {
    const items = [];

    // First reason gets AI explanation merged in
    if (reasons.length > 0) {
      const first = reasons[0];
      const text = typeof first === "string" ? first : first.reason;
      let detail = typeof first === "string" ? "" : (first.detail || "");

      // If AI explanation is available, prepend it to the first reason's detail
      if (explanation?.reason) {
        detail = explanation.reason + (detail ? "\n\n" + detail : "");
      }

      if (detail) {
        items.push(renderExpandable(text, detail));
      } else {
        items.push(`<div class="reason">${escapeHtml(text)}</div>`);
      }
    } else if (explanation?.reason) {
      // No heuristic reasons but AI explanation exists
      items.push(renderExpandable(explanation.headline || "Analysis", explanation.reason));
    }

    // Remaining reasons
    for (let i = 1; i < reasons.length; i++) {
      const r = reasons[i];
      const text = typeof r === "string" ? r : r.reason;
      const detail = typeof r === "string" ? "" : (r.detail || "");
      if (detail) {
        items.push(renderExpandable(text, detail));
      } else {
        items.push(`<div class="reason">${escapeHtml(text)}</div>`);
      }
    }

    // Loading indicator if AI is still working
    if (aiLoading && !explanation) {
      items.push(`<div class="loading" style="padding: 8px 12px; font-size: 12px;">Analyzing with AI...</div>`);
    }

    reasonsHtml = `
      <div class="card">
        <div class="pill muted">Top Reasons</div>
        ${items.join("")}
      </div>
    `;
  }

  app.innerHTML = `
    <div class="header">
      <span>🛡️</span>
      <span class="brand">ScamShield</span>
    </div>

    <div class="card" style="background:${theme.bg}; border-color:${theme.color};">
      <div class="pill" style="color:${theme.color};">${theme.label}</div>
      <div class="score" style="color:${theme.color};">${scan?.score ?? "--"}% safe</div>
      <div class="muted">${status === "scanning" ? "Scanning page..." : "Safety score"}</div>
      <div class="bar">
        <div class="bar-fill" style="width:${scan?.score ?? 0}%; background:${theme.color};"></div>
      </div>
    </div>

    ${reasonsHtml}

    ${explanation?.recommended_action ? `
      <div class="card">
        <div class="pill muted">Recommended Action</div>
        <div style="font-size:13px; color:#d1d5db; line-height:1.5;">${escapeHtml(explanation.recommended_action)}</div>
      </div>
    ` : ""}

    ${scan?.url ? `
      <div class="card">
        <div class="pill muted">Page URL</div>
        <div class="muted" style="word-break:break-all;">${escapeHtml(scan.url)}</div>
      </div>
    ` : ""}
  `;

  // Wire up expandable reason clicks (CSP-safe)
  app.querySelectorAll(".reason-expandable").forEach((el) => {
    el.addEventListener("click", () => {
      el.classList.toggle("expanded");
    });
  });
}

function renderExpandable(text, detail) {
  return `<div class="reason-expandable">
    <div class="reason-header">${escapeHtml(text)}</div>
    <div class="reason-detail">${escapeHtml(detail)}</div>
  </div>`;
}

async function refresh() {
  const state = await chrome.storage.session.get(["lastPageResult", "scanStatus"]);
  render(state);
}

chrome.storage.session.onChanged.addListener(refresh);

refresh();

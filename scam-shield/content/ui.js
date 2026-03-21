(function () {
  if (window.ScamShieldUI) return;

  function removeWarningUI() {
    document.getElementById("scamshield-danger-overlay")?.remove();
    document.getElementById("scamshield-suspicious-banner")?.remove();
  }

  function showDangerOverlay({ href, score, reason, onProceed }) {
    removeWarningUI();

    const overlay = document.createElement("div");
    overlay.id = "scamshield-danger-overlay";
    overlay.innerHTML = `
      <div style="
        position: fixed; inset: 0; z-index: 2147483647;
        background: rgba(0, 0, 0, 0.78); display: flex;
        align-items: center; justify-content: center;
        font-family: system-ui, sans-serif;
      ">
        <div style="
          width: min(500px, 92vw); background: #111827; color: white;
          border: 2px solid #ef4444; border-radius: 14px; padding: 24px;
          box-shadow: 0 20px 50px rgba(0,0,0,0.35);
        ">
          <div style="font-size: 1.9rem; font-weight: 800; color: #ef4444;">Dangerous Link</div>
          <div style="margin-top: 8px; color: #fca5a5; font-size: 1rem;">
            Risk Score: ${score}/100
          </div>
          <div style="margin-top: 12px; color: #d1d5db; font-size: 0.85rem; word-break: break-all;">
            ${href}
          </div>
          <div id="ss-danger-reason" style="margin-top: 10px; color: #9ca3af; font-size: 0.95rem;">
            ${reason || ""}
          </div>
          <div style="display: flex; gap: 12px; margin-top: 24px;">
            <button id="ss-go-back" style="
              flex: 1; padding: 12px; background: #ef4444; color: white;
              border: none; border-radius: 8px; cursor: pointer; font-size: 1rem;
            ">Go Back</button>
            <button id="ss-proceed" style="
              flex: 1; padding: 12px; background: transparent; color: white;
              border: 1px solid #4b5563; border-radius: 8px; cursor: pointer; font-size: 1rem;
            ">Proceed Anyway</button>
          </div>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector("#ss-go-back").onclick = () => {
      overlay.remove();
      history.back();
    };
    overlay.querySelector("#ss-proceed").onclick = () => {
      overlay.remove();
      onProceed();
    };
  }

  function showSuspiciousBanner({ score, onOpenPanel }) {
    if (document.getElementById("scamshield-suspicious-banner")) return;

    const banner = document.createElement("div");
    banner.id = "scamshield-suspicious-banner";
    banner.innerHTML = `
      <div style="
        position: fixed; top: 0; left: 0; right: 0; z-index: 2147483646;
        background: #f59e0b; color: #111827; padding: 12px 16px;
        display: flex; align-items: center; justify-content: space-between;
        gap: 12px; font: 600 14px system-ui, sans-serif;
        box-shadow: 0 6px 20px rgba(0,0,0,0.2);
      ">
        <span>Suspicious page detected (${score}/100)</span>
        <div style="display: flex; gap: 8px;">
          <button id="ss-open-panel" style="
            padding: 8px 12px; border: none; border-radius: 8px;
            background: #111827; color: white; cursor: pointer;
          ">Open Details</button>
          <button id="ss-dismiss-banner" style="
            padding: 8px 10px; border: 1px solid rgba(17, 24, 39, 0.2);
            border-radius: 8px; background: transparent; color: #111827; cursor: pointer;
          ">Dismiss</button>
        </div>
      </div>
    `;

    document.body.appendChild(banner);
    banner.querySelector("#ss-open-panel").onclick = onOpenPanel;
    banner.querySelector("#ss-dismiss-banner").onclick = () => banner.remove();
  }

  window.ScamShieldUI = {
    removeWarningUI,
    showDangerOverlay,
    showSuspiciousBanner,
  };
})();

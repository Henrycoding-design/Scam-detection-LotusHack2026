import { useEffect, useState } from "react";
import "./App.css";

const VERDICT_CONFIG = {
  safe:       { color: "#22c55e", bg: "#052e16", label: "Safe",       icon: "✅" },
  suspicious: { color: "#f59e0b", bg: "#1c1100", label: "Suspicious", icon: "⚠️" },
  dangerous:  { color: "#ef4444", bg: "#1c0000", label: "Dangerous",  icon: "🚨" },
  scanning:   { color: "#6b7280", bg: "#111",    label: "Scanning…",  icon: "🔍" },
};

export default function App() {
  const [scan, setScan] = useState(null);
  const [status, setStatus] = useState("scanning");

  useEffect(() => {
    // Load last scan immediately
    if (window.chrome && chrome.storage && chrome.storage.session) {
      chrome.storage.session.get(["lastScan"], (result) => {
        if (result.lastScan) {
          setScan(result.lastScan);
          setStatus(result.lastScan.verdict);
        }
      });

      // Watch for updates
      const listener = (changes) => {
        if (changes.lastScan?.newValue) {
          const s = changes.lastScan.newValue;
          setScan(s);
          setStatus(s.verdict);
        }
      };
      chrome.storage.session.onChanged.addListener(listener);
      return () => chrome.storage.session.onChanged.removeListener(listener);
    }
  }, []);

  const config = VERDICT_CONFIG[status] || VERDICT_CONFIG.scanning;

  return (
    <div style={{
      fontFamily: "system-ui, sans-serif",
      background: "#0f0f13",
      minHeight: "100vh",
      padding: "16px",
      color: "white",
    }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 20 }}>
        <span style={{ fontSize: 20 }}>🛡️</span>
        <span style={{ fontWeight: 700, fontSize: 16, color: "#a78bfa" }}>ScamShield</span>
      </div>

      {/* Verdict Card */}
      <div style={{
        background: config.bg,
        border: `1.5px solid ${config.color}`,
        borderRadius: 12,
        padding: "20px 16px",
        marginBottom: 16,
        textAlign: "center",
      }}>
        <div style={{ fontSize: 36, marginBottom: 6 }}>{config.icon}</div>
        <div style={{ color: config.color, fontWeight: 700, fontSize: 22 }}>
          {config.label}
        </div>
        {scan && (
          <div style={{ color: "#9ca3af", fontSize: 13, marginTop: 4 }}>
            Risk Score: <span style={{ color: config.color, fontWeight: 600 }}>
              {scan.score}/100
            </span>
          </div>
        )}
      </div>

      {/* Score bar */}
      {scan && (
        <div style={{ marginBottom: 16 }}>
          <div style={{
            height: 6, background: "#1f2937", borderRadius: 99, overflow: "hidden",
          }}>
            <div style={{
              height: "100%",
              width: `${scan.score}%`,
              background: config.color,
              borderRadius: 99,
              transition: "width 0.6s ease",
            }} />
          </div>
        </div>
      )}

      {/* Reasons */}
      {scan?.reasons?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ color: "#6b7280", fontSize: 11, fontWeight: 600,
            textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>
            Why we flagged this
          </div>
          {scan.reasons.map((r, i) => (
            <div key={i} style={{
              background: "#1a1a2a",
              borderRadius: 8,
              padding: "10px 12px",
              marginBottom: 6,
              fontSize: 13,
              color: "#d1d5db",
              borderLeft: `3px solid ${config.color}`,
            }}>
              {r}
            </div>
          ))}
        </div>
      )}

      {/* Explanation */}
      {scan?.explanation && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ color: "#6b7280", fontSize: 11, fontWeight: 600,
            textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>
            AI Analysis
          </div>
          <div style={{
            background: "#1a1a2a",
            borderRadius: 8,
            padding: "10px 12px",
            fontSize: 13,
            color: "#d1d5db",
            borderLeft: `3px solid #a78bfa`,
          }}>
            <strong>{scan.explanation.headline}</strong>
            <p style={{ marginTop: 4, marginBottom: 4 }}>{scan.explanation.reason}</p>
            <em style={{ color: "#9ca3af" }}>{scan.explanation.recommended_action}</em>
          </div>
        </div>
      )}

      {/* URL */}
      {scan?.url && (
        <div style={{
          background: "#111", borderRadius: 8, padding: "8px 10px",
          fontSize: 11, color: "#6b7280", wordBreak: "break-all",
          marginBottom: 16,
        }}>
          {scan.url}
        </div>
      )}

      {/* Action buttons — only show if suspicious/dangerous */}
      {(status === "suspicious" || status === "dangerous") && (
        <div style={{ display: "flex", gap: 8 }}>
          <button
            onClick={() => window.history.back()}
            style={{
              flex: 1, padding: "12px 0", borderRadius: 8, border: "none",
              background: "#ef4444", color: "white", fontWeight: 600,
              cursor: "pointer", fontSize: 13,
            }}>
            ← Go Back
          </button>
          <button
            onClick={() => setStatus("safe")}
            style={{
              flex: 1, padding: "12px 0", borderRadius: 8,
              border: "1px solid #374151",
              background: "transparent", color: "#9ca3af",
              cursor: "pointer", fontSize: 13,
            }}>
            Ignore Once
          </button>
        </div>
      )}

      {/* No scan yet */}
      {!scan && (
        <div style={{ textAlign: "center", color: "#4b5563", fontSize: 13, marginTop: 40 }}>
          Navigate to a page to begin scanning
        </div>
      )}
    </div>
  );
}

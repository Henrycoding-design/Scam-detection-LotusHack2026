/// <reference types="vite/client" />
import { useEffect, useState } from "react";
import { createClient } from "@supabase/supabase-js";

// We'll use dummy client if keys are missing so it doesn't crash during dev
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || "https://dummy.supabase.co";
const supabaseKey = import.meta.env.VITE_SUPABASE_ANON_KEY || "dummy-key";

const sb = createClient(supabaseUrl, supabaseKey);

const COLORS = { safe: "#22c55e", suspicious: "#f59e0b", dangerous: "#ef4444" };

export default function App() {
  const [scans, setScans] = useState([]);

  useEffect(() => {
    if (!import.meta.env.VITE_SUPABASE_URL) {
      setScans([
        { id: 1, verdict: "dangerous", risk: 85, created_at: new Date().toISOString(), url: "http://192.168.1.1/paypal-secure-login", reasons: ["Link goes directly to an IP address", "Domain impersonates \"paypal\""] },
        { id: 2, verdict: "suspicious", risk: 45, created_at: new Date().toISOString(), url: "http://example.com/login", reasons: ["Login pattern on unrecognized domain"] },
        { id: 3, verdict: "safe", risk: 0, created_at: new Date().toISOString(), url: "http://localhost:3000", reasons: [] },
      ]);
      return;
    }

    sb.from("scans")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(10)
      .then(({ data }) => setScans(data || []));
  }, []);

  return (
    <div style={{ maxWidth: 720, margin: "0 auto", padding: "32px 16px",
      fontFamily: "system-ui", background: "#0f0f13", minHeight: "100vh", color: "white" }}>
      <h1 style={{ color: "#a78bfa" }}>🛡️ ScamShield — Scan History</h1>
      {scans.map((s) => (
        <div key={s.id} style={{
          background: "#1a1a2a", borderRadius: 10, padding: 16, marginBottom: 12,
          borderLeft: `4px solid ${COLORS[s.verdict] || "#555"}`,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <span style={{ color: COLORS[s.verdict], fontWeight: 700 }}>
              {s.verdict.toUpperCase()} — {s.risk}/100
            </span>
            <span style={{ color: "#6b7280", fontSize: 12 }}>
              {new Date(s.created_at).toLocaleTimeString()}
            </span>
          </div>
          <div style={{ color: "#9ca3af", fontSize: 12, marginTop: 6, wordBreak: "break-all" }}>
            {s.url}
          </div>
          {s.reasons?.map((r, i) => (
            <div key={i} style={{ color: "#d1d5db", fontSize: 12, marginTop: 4 }}>
              • {r}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

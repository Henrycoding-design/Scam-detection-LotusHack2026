import { createClient } from "@supabase/supabase-js";

// We'll use dummy client if keys are missing so it doesn't crash during dev
const supabaseUrl = process.env.SUPABASE_URL || "https://dummy.supabase.co";
const supabaseKey = process.env.SUPABASE_ANON_KEY || "dummy-key";

const supabase = createClient(supabaseUrl, supabaseKey);

export async function saveScan({ url, score, verdict, reasons, signals }) {
  if (!process.env.SUPABASE_URL) {
    console.log("[Supabase Mock] Saved scan:", { url, score, verdict });
    return "mock-id";
  }

  // Insert scan row
  const { data: scan, error } = await supabase
    .from("scans")
    .insert({ url, risk: score, verdict, reasons })
    .select("id")
    .single();

  if (error) throw error;

  // Insert signal rows in bulk
  if (signals && signals.length > 0) {
    await supabase.from("signals").insert(
      signals.map((s) => ({
        scan_id: scan.id,
        type: s.type,
        weight: s.weight,
        reason: s.reason,
      }))
    );
  }

  return scan.id;
}

export async function getRecentScans(limit = 10) {
  if (!process.env.SUPABASE_URL) {
    return [];
  }

  const { data } = await supabase
    .from("scans")
    .select("*, signals(*)")
    .order("created_at", { ascending: false })
    .limit(limit);
  return data || [];
}

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { runScoring } from "./backend/scoring/score.js";
import { saveScan } from "./backend/lib/supabase.js";
import { getGeminiExplanation } from "./backend/scoring/gemini.js";
import { createServer as createViteServer } from "vite";
import path from "path";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.post("/analyze", async (req, res) => {
  const { url, links = [], text = "", event = "load" } = req.body;

  if (!url) return res.status(400).json({ error: "url required" });

  try {
    const { score, verdict, reasons, signals } = runScoring({ url, links, text });
    
    let explanation = null;
    if (score >= 30) {
      explanation = await getGeminiExplanation({ url, score, signals, visibleText: text });
    }

    // Save to Supabase async — don't block the response
    saveScan({ url, score, verdict, reasons, signals }).catch(console.error);

    return res.json({ risk: score, verdict, reasons, explanation, signals });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "scoring failed" });
  }
});

app.get("/health", (_, res) => res.json({ ok: true }));

async function startServer() {
  const PORT = Number(process.env.PORT) || 3000;

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`ScamShield API running on http://localhost:${PORT}`);
  });
}

startServer();

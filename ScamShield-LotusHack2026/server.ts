import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { runScoring } from "./backend/scoring/score.js";
import { saveScan } from "./backend/lib/supabase.js";
import { getOpenAIExplanation } from "./backend/scoring/gemini.js";
import { buildAnalysisPayload } from "./scam-shield/scoring/analysis.js";
import { createServer as createViteServer } from "vite";
import path from "path";
import { pathToFileURL } from "url";

dotenv.config();
const DEFAULT_DEPS = {
  runScoring,
  saveScan,
  getExplanation: getOpenAIExplanation,
};

type HttpError = Error & { statusCode: number };

function createHttpError(message: string, statusCode: number): HttpError {
  const error = new Error(message) as HttpError;
  error.statusCode = statusCode;
  return error;
}

function isHttpError(error: unknown): error is HttpError {
  return Boolean(
    error &&
      typeof error === "object" &&
      "statusCode" in error &&
      typeof error.statusCode === "number"
  );
}

export async function analyzeScan(
  { url, links = [], text = "" },
  dependencies = DEFAULT_DEPS
) {
  if (!url) {
    throw createHttpError("url required", 400);
  }

  const { score, verdict, reasons, signals } = dependencies.runScoring({
    url,
    links,
    text,
  });

  let explanation = null;
  if (score >= 30) {
    explanation = await dependencies.getExplanation({
      url,
      score,
      signals,
      visibleText: text,
      subjectType: "page",
    });
  }

  const analysis = buildAnalysisPayload({
    subjectType: "page",
    url,
    score,
    signals,
    aiStatus: score >= 30 ? (explanation ? "ready" : "unavailable") : "skipped",
    explanation,
  });

  dependencies
    .saveScan({ url, score, verdict, reasons, signals })
    .catch(console.error);

  return {
    risk: score,
    verdict,
    reasons,
    explanation,
    signals,
    analysis,
  };
}

export function createApp(dependencies = DEFAULT_DEPS) {
  const app = express();
  app.use(cors());
  app.use(express.json({ limit: "1mb" }));

  app.post("/analyze", async (req, res) => {
    const { url, links = [], text = "" } = req.body;

    if (!url) {
      return res.status(400).json({ error: "url required" });
    }

    try {
      const response = await analyzeScan({ url, links, text }, dependencies);
      return res.json(response);
    } catch (err) {
      if (isHttpError(err) && err.statusCode === 400) {
        return res.status(400).json({ error: err.message });
      }
      console.error(err);
      return res.status(500).json({ error: "scoring failed" });
    }
  });

  app.get("/health", (_, res) => res.json({ ok: true }));
  return app;
}

export async function startServer() {
  const app = createApp();
  const PORT = Number(process.env.PORT) || 3000;

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

const isDirectRun =
  process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;

if (isDirectRun) {
  startServer();
}

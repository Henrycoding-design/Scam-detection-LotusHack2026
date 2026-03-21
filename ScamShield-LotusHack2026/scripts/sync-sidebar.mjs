import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";

const root = process.cwd();
const sourceDir = path.join(root, "sidebar", "dist");
const targetDir = path.join(root, "scam-shield", "sidebar");

if (!existsSync(sourceDir)) {
  throw new Error(`Sidebar build output not found: ${sourceDir}`);
}

mkdirSync(path.dirname(targetDir), { recursive: true });
rmSync(targetDir, { recursive: true, force: true });
cpSync(sourceDir, targetDir, { recursive: true });

console.log(`Synced sidebar build to ${targetDir}`);

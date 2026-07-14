import { cp, mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const sourceDir = path.join(root, "src");
const outputDir = path.join(root, "dist");

const check = spawnSync(process.execPath, [path.join(root, "scripts/check.mjs")], {
  stdio: "inherit"
});
if (check.status !== 0) process.exit(check.status ?? 1);

await rm(outputDir, { recursive: true, force: true });
await mkdir(outputDir, { recursive: true });
await cp(sourceDir, outputDir, { recursive: true });

console.log(`Built Chrome extension: ${path.relative(root, outputDir)}/`);

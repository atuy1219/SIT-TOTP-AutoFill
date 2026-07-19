import { cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawnSync } from "node:child_process";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const sourceDir = path.join(root, "src");
const distDir = path.join(root, "dist");
const supportedTargets = new Set(["chromium", "firefox"]);
const requestedTarget = process.argv[2] ?? "all";

if (requestedTarget !== "all" && !supportedTargets.has(requestedTarget)) {
  console.error(`Unknown target: ${requestedTarget}. Use chromium, firefox, or all.`);
  process.exit(1);
}

const check = spawnSync(process.execPath, [path.join(root, "scripts/check.mjs")], {
  stdio: "inherit"
});
if (check.status !== 0) process.exit(check.status ?? 1);

async function collectJavaScriptFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await collectJavaScriptFiles(absolute));
    else if (entry.isFile() && entry.name.endsWith(".js")) files.push(absolute);
  }
  return files;
}

async function buildTarget(target) {
  const outputDir = path.join(distDir, target);
  await rm(outputDir, { recursive: true, force: true });
  await mkdir(outputDir, { recursive: true });
  await cp(sourceDir, outputDir, { recursive: true });

  if (target === "firefox") {
    const manifestPath = path.join(outputDir, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    const backgroundScript = manifest.background?.service_worker
      ?? manifest.background?.scripts?.[0]
      ?? "background.js";

    delete manifest.minimum_chrome_version;
    manifest.background = { scripts: [backgroundScript] };
    manifest.browser_specific_settings = {
      gecko: {
        id: "sit-totp-autofill@atuy1219.github.io",
        strict_min_version: "115.0",
        data_collection_permissions: {
          required: ["none"]
        }
      }
    };

    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    for (const file of await collectJavaScriptFiles(outputDir)) {
      const source = await readFile(file, "utf8");
      await writeFile(file, source.replace(/\bchrome\./g, "browser."));
    }
  }

  console.log(`Built ${target} extension: ${path.relative(root, outputDir)}/`);
}

if (requestedTarget === "all") {
  await rm(distDir, { recursive: true, force: true });
  await Promise.all([...supportedTargets].map(buildTarget));
} else {
  await mkdir(distDir, { recursive: true });
  await buildTarget(requestedTarget);
}

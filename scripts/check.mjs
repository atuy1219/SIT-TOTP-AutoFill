import { access, readFile, readdir } from "node:fs/promises";
import { constants } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const root = path.resolve(import.meta.dirname, "..");
const sourceDir = path.join(root, "src");
const manifestPath = path.join(sourceDir, "manifest.json");
const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));

function fail(message) {
  console.error(`ERROR: ${message}`);
  process.exitCode = 1;
}

async function collectFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await collectFiles(absolute));
    else if (entry.isFile()) files.push(absolute);
  }
  return files;
}

async function requireFile(relativePath) {
  const absolute = path.join(sourceDir, relativePath);
  try {
    await access(absolute, constants.R_OK);
  } catch {
    fail(`manifest.json refers to a missing file: src/${relativePath}`);
  }
}

let manifest;
try {
  manifest = JSON.parse(await readFile(manifestPath, "utf8"));
} catch (error) {
  fail(`src/manifest.json is invalid: ${error.message}`);
  process.exit();
}

if (manifest.manifest_version !== 3) {
  fail("manifest_version must be 3.");
}
if (manifest.version !== packageJson.version) {
  fail(`manifest version (${manifest.version}) does not match package version (${packageJson.version}).`);
}

const referencedFiles = new Set();
if (manifest.background?.service_worker) referencedFiles.add(manifest.background.service_worker);
for (const script of manifest.background?.scripts ?? []) referencedFiles.add(script);
if (manifest.action?.default_popup) referencedFiles.add(manifest.action.default_popup);
if (manifest.options_page) referencedFiles.add(manifest.options_page);
for (const script of manifest.content_scripts ?? []) {
  for (const js of script.js ?? []) referencedFiles.add(js);
  for (const css of script.css ?? []) referencedFiles.add(css);
}
for (const iconMap of [manifest.icons, manifest.action?.default_icon]) {
  for (const icon of Object.values(iconMap ?? {})) referencedFiles.add(icon);
}

await Promise.all([...referencedFiles].map(requireFile));

const files = await collectFiles(sourceDir);
for (const file of files.filter((file) => file.endsWith(".js"))) {
  const result = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
  if (result.status !== 0) {
    fail(`${path.relative(root, file)} has a syntax error:\n${result.stderr.trim()}`);
  }
}

if (!process.exitCode) {
  console.log(`Validated ${files.length} source files for Chromium and Firefox MV3 builds.`);
}

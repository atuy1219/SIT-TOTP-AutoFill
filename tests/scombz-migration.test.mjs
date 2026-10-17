import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const background = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
test("startup removes the persistent experimental rule without installing redirects", async () => {
  const start = background.indexOf("async function scombzRemoveLegacyRule()");
  const end = background.indexOf("function isTargetSender", start);
  const updates = [];
  vm.runInNewContext(background.slice(start, end), {
    chrome: { declarativeNetRequest: {
      updateDynamicRules: async (update) => updates.push(update)
    } }
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(JSON.parse(JSON.stringify(updates)), [{ removeRuleIds: [7302] }]);
});

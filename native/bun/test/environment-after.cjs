"use strict";
const assert = require("node:assert/strict");
const test = globalThis.__wrapperEnvironmentTest;
module.exports = function verifyEnvironment() {
  const original = test.references.savedProcess;
  const controlled = [
    "TZ", "TZDIR", "TZFILE", "LANG", "LC_ALL", "LANGUAGE", "CLAUDE_CONFIG_DIR",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING",
    "CLAUDE_CODE_ENABLE_TELEMETRY", "DO_NOT_TRACK",
  ];
  assert.deepEqual(test.missingBefore, { own: false, in: false, enumerable: false });
  assert.equal(Object.hasOwn(original, "CLAUDE_WRAPPER_ENV_LOCK_CAPABILITY_PROBE"), false);
  const tz = Object.getOwnPropertyDescriptor(original, "TZ");
  const capable = tz?.writable === false && tz.configurable === false;
  const unrelated = "CLAUDE_WRAPPER_UNRELATED_ENV_TEST";
  for (const reference of Object.values(test.references)) {
    reference[unrelated] = "first";
    reference[unrelated] = "second";
    assert.equal(reference[unrelated], "second");
    assert.equal(delete reference[unrelated], true);
    assert.equal(reference[unrelated], undefined);
  }
  if (!capable) {
    // Demonstrate the gap, then restore the test value. This is not a pass for
    // complete alias protection, even though the common process.env path works.
    const exposed = [];
    for (const [label, reference] of Object.entries(test.references)) {
      reference.TZFILE = "/wrapper-test-untrusted-timezone";
      if (reference.TZFILE === "/wrapper-test-untrusted-timezone") exposed.push(label);
      delete reference.TZFILE;
    }
    assert.deepEqual(exposed.sort(), Object.keys(test.references).sort());
    process.stderr.write("BUN_ENV_ALIAS_PROTECTION_UNAVAILABLE " + JSON.stringify({ bun: process.versions.bun, exposed }) + "\n");
    process.exitCode = 3;
    return;
  }
  for (const [label, reference] of Object.entries(test.references)) {
    for (const key of controlled) {
      const value = reference[key];
      assert.throws(() => { reference[key] = "wrapper-test-different-value"; }, TypeError, `${label}.${key}`);
      assert.equal(reference[key], value);
      // Raw readonly aliases also reject same-value assignment. This is a
      // deliberate compatibility cost of locking the shared original object.
      assert.throws(() => { reference[key] = value; }, TypeError, `same value ${label}.${key}`);
      assert.equal(reference[key], value);
      assert.throws(() => { delete reference[key]; }, TypeError, `delete ${label}.${key}`);
      assert.equal(reference[key], value);
    }
  }
  // Missing fields remain undefined, but locking creates a hidden own slot.
  assert.equal(original.TZFILE, undefined);
  assert.equal(Object.hasOwn(original, "TZFILE"), true);
  assert.equal("TZFILE" in original, true);
  assert.equal(Object.keys(original).includes("TZFILE"), false);
  assert.equal(Reflect.ownKeys(original).includes("TZFILE"), true);
  for (const key of ["TZDIR", "TZFILE", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK"]) {
    const command = ["/usr/bin/printenv", key];
    for (const result of [
      Bun.spawnSync(command, { stdout: "pipe", stderr: "pipe" }),
      Bun.spawnSync(command, { env: original, stdout: "pipe", stderr: "pipe" }),
      require("node:child_process").spawnSync(command[0], command.slice(1), { env: original }),
    ]) {
      assert.equal(result.status ?? result.exitCode, 1);
      assert.equal(String(result.stdout), "");
    }
  }
  process.env.TZ = process.env.TZ;
  process.env.TZFILE = undefined;
  assert.equal(process.env.TZFILE, undefined);
  assert.throws(() => { delete process.env.TZFILE; }, TypeError);
  assert.throws(() => { process.env.TZ = new String(process.env.TZ); }, TypeError);
  process.stderr.write("BUN_ENV_ALIASES_LOCKED " + JSON.stringify({ bun: process.versions.bun,
    missingOwnSlots: true, undefinedOmittedFromChildren: true,
    proxySameValueAllowed: true, readonlyAliasSameValueRejected: true,
    absentControlledDeleteRejected: true, boxedSameStringRejected: true }) + "\n");
  delete globalThis.__wrapperEnvironmentTest;
};

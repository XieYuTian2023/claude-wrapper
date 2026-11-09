"use strict";
// Test-only preload for an actual official Bun-compiled Claude --help process.
// Capture raw libc getenv before provider initialization, then verify on exit.
// This emits only booleans and variable names, never environment values.
const {dlopen, FFIType: T} = require("bun:ffi");
const cp = require("node:child_process");
const names = ["TERM_SESSION_ID", "ITERM_SESSION_ID", "SECURITYSESSIONID", "XPC_SERVICE_NAME",
  "LaunchInstanceID", "__CFBundleIdentifier", "CODEX_SESSION_ID", "STARSHIP_SESSION_KEY"];
const references = {
  savedProcess: process.env,
  savedBun: Bun.env,
  savedRequireProcess: require("process").env,
  savedNodeProcess: require("node:process").env,
};
const raw = dlopen("/usr/lib/libSystem.B.dylib", {getenv: {args: [T.ptr], returns: T.ptr}});
const expectedPresent = process.env.WRAPPER_SESSION_PROBE_EXPECT === "present";
const childSource = `import ctypes,json,os
names=${JSON.stringify(names)}
native=ctypes.CDLL(None).getenv
native.argtypes=[ctypes.c_char_p]
native.restype=ctypes.c_void_p
print(json.dumps([{'name':name,'defined':name in os.environ,'nativePresent':bool(native(name.encode()))} for name in names]))`;

function verifySessionMarkers() {
  const snapshots = Object.fromEntries(Object.entries({...references, currentProcess: process.env, currentBun: Bun.env})
    .map(([label, env]) => [label, names.map(name => ({name, defined: env[name] !== undefined,
      enumerable: Object.keys(env).includes(name), own: Object.hasOwn(env, name)}))]));
  const native = names.map(name => ({name, present: raw.symbols.getenv(Buffer.from(name + "\0")) != null}));
  const children = [];
  for (const [kind, run] of [
    ["node_default_environment", () => cp.spawnSync("/usr/bin/python3", ["-c", childSource], {encoding: "utf8"})],
    ["node_saved_environment", () => cp.spawnSync("/usr/bin/python3", ["-c", childSource], {env: references.savedProcess, encoding: "utf8"})],
    ["bun_default_environment", () => Bun.spawnSync(["/usr/bin/python3", "-c", childSource], {stdout: "pipe", stderr: "pipe"})],
    ["bun_saved_environment", () => Bun.spawnSync(["/usr/bin/python3", "-c", childSource], {env: references.savedProcess, stdout: "pipe", stderr: "pipe"})],
  ]) {
    try {
      const result = run();
      children.push({kind, exit: result.status ?? result.exitCode, variables: JSON.parse(String(result.stdout))});
    } catch (error) {
      children.push({kind, failed: true, errorType: error.constructor.name});
    }
  }
  const passed = Object.values(snapshots).every(rows => rows.every(row => row.defined === expectedPresent))
    && native.every(row => row.present === expectedPresent)
    && children.every(child => child.exit === 0 && child.variables.every(row =>
      row.defined === expectedPresent && row.nativePresent === expectedPresent));
  const result = {expectedPresent, passed, snapshots, native, children};
  process.stderr.write("SESSION_MARKERS_RESULT " + JSON.stringify(result) + "\n");
  if (!passed) process.exitCode = 1;
  return result;
}
module.exports = {names, verifySessionMarkers};
if (process.env.WRAPPER_SESSION_PROBE_AUTO === "1") process.once("exit", verifySessionMarkers);

"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const original = globalThis.__wrapperTestOriginals;
module.exports = function verify(applicationUserReads) {
const expected = process.env.USER;
assert.equal(os.hostname(), process.env.HOSTNAME);
assert.equal(original.os.hostname(), process.env.HOSTNAME,
  "the original hostname function must see the host");
const native = globalThis[Symbol.for("claude-wrapper.native-provider")];
assert(native, "native provider must remain loaded");
const {dlopen, CString} = require("bun:ffi");
const c = dlopen("/usr/lib/libSystem.B.dylib", {getenv: {args: ["ptr"], returns: "ptr"}});
const nativeEnv = key => {
  const pointer = c.symbols.getenv(Buffer.from(key + "\0"));
  return pointer === null ? undefined : String(new CString(pointer));
};
for (const key of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "BUN_OPTIONS"])
  assert.equal(nativeEnv(key), process.env[key], `native and JS environments differ: ${key}`);
for (const key of ["CLAUDE_WRAPPER_PROXY_URL", "CLAUDE_WRAPPER_READY_FD", "CLAUDE_WRAPPER_PRELOAD_FD", "CLAUDE_WRAPPER_DEVICE_ID", "CLAUDE_WRAPPER_NATIVE_LIBRARY", "CLAUDE_WRAPPER_INIT_OWNER"])
  assert.equal(nativeEnv(key), undefined, `native bootstrap value remains: ${key}`);
const status = Buffer.alloc(160);
assert.equal(native.symbols.claude_wrapper_get_status(status, 160n), 0);
assert.equal(status.readBigUInt64LE(3 * 8), 224n);
for (const index of [7, 12, 13, 14, 15, 18]) assert.equal(status.readBigUInt64LE(index * 8), 0n);
for (const encoding of ["utf8", "buffer", "hex", "latin1", "utf16le"]) {
  assert.deepEqual(os.userInfo({encoding}), original.os.userInfo({encoding}));
}
assert.equal(os.userInfo().username, expected);
for (const options of [{encoding:"unknown-encoding"}, 42]) {
  let before, after;
  try { original.os.userInfo(options); } catch (error) { before = [error.name, error.code]; }
  try { os.userInfo(options); } catch (error) { after = [error.name, error.code]; }
  assert.deepEqual(after, before);
}
let reads = 0;
os.userInfo({get encoding() { reads++; return "utf8"; }});
let nativeReads = 0;
original.os.userInfo({get encoding() { nativeReads++; return "utf8"; }});
assert.equal(reads, nativeReads);
for (const [key, value] of Object.entries(original.fs)) assert.equal(fs[key], value);
for (const [key, value] of Object.entries(original.promises)) assert.equal(fs.promises[key], value);
assert.equal(Bun.file, original.bunFile);
assert.equal(Bun.write, original.bunWrite);
const filename = require("node:path").join(process.env.CLAUDE_CONFIG_DIR, "native file.txt");
fs.writeFileSync(filename, "unchanged file API");
assert.equal(original.fs.readFileSync(filename, "utf8"), "unchanged file API");
assert.equal(fs.statSync(filename).ino, original.fs.statSync(filename).ino);
for (const key of ["CLAUDE_WRAPPER_HOSTNAME", "CLAUDE_WRAPPER_USERNAME", "CLAUDE_WRAPPER_READY_FD", "CLAUDE_WRAPPER_DEVICE_ID"]) {
  assert.equal(process.env[key], undefined);
}
assert(applicationUserReads > 0, "expected an actual Claude Code userInfo read before fixture checks");
process.stderr.write("BUN_IDENTITY_CONTRACT_OK\n");
delete globalThis.__wrapperTestOriginals;
};

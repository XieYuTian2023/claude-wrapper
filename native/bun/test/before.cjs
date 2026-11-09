"use strict";
const os = require("node:os");
const fs = require("node:fs");
globalThis.__wrapperTestOriginals = {
  os: { hostname: os.hostname, userInfo: os.userInfo },
  fs: Object.fromEntries(["openSync", "readFileSync", "writeFileSync", "statSync", "realpathSync", "readdirSync"].map(key => [key, fs[key]])),
  promises: Object.fromEntries(["open", "readFile", "writeFile", "stat", "realpath", "readdir"].map(key => [key, fs.promises[key]])),
  bunFile: Bun.file,
  bunWrite: Bun.write,
};
let applicationUserReads = 0;
const userInfo = os.userInfo;
os.userInfo = function(options) {
  applicationUserReads++;
  return userInfo(options);
};
require("node:module").syncBuiltinESMExports();
process.on("exit", () => require("./after.cjs")(applicationUserReads));

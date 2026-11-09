"use strict";
const key = "TZFILE";
globalThis.__wrapperEnvironmentTest = {
  references: {
    savedProcess: process.env,
    savedBun: Bun.env,
    savedMeta: import.meta.env,
    savedModule: require("bun").env,
  },
  missingBefore: {
    own: Object.hasOwn(process.env, key),
    in: key in process.env,
    enumerable: Object.keys(process.env).includes(key),
  },
};
process.on("exit", () => require("./environment-after.cjs")());

"use strict";

// Bun's documented preload entry customizes this process without wrapping file APIs.
const fs = require("node:fs");

function fail() {
  process.stderr.write("identity-launch: Bun identity initialization failed\n");
  process.exit(126);
}

try {
  const timezone = process.env.TZ;
  const locale = process.env.LC_ALL || process.env.LANG;
  const ready = process.env.CLAUDE_WRAPPER_READY_FD;
  const preload = process.env.CLAUDE_WRAPPER_PRELOAD_FD;
  const proxy = process.env.CLAUDE_WRAPPER_PROXY_URL;
  const deviceId = process.env.CLAUDE_WRAPPER_DEVICE_ID;
  const previousOptions = process.env.CLAUDE_WRAPPER_ORIGINAL_BUN_OPTIONS;
  const nativeLibrary = process.env.CLAUDE_WRAPPER_NATIVE_LIBRARY;

  if (!timezone || !locale || !process.versions.bun ||
      !deviceId || !/^[0-9a-f]{64}$/.test(deviceId)) {
    fail();
  }
  const expectedTimezone = new Intl.DateTimeFormat("en-US", { timeZone: timezone })
    .resolvedOptions().timeZone;
  const expectedLocale = Intl.getCanonicalLocales(locale.replace(/\.UTF-8$/, "").replace("_", "-"))[0];
  const actual = new Intl.DateTimeFormat().resolvedOptions();
  if (actual.timeZone !== expectedTimezone || actual.locale !== expectedLocale) {
    fail();
  }

  if (!nativeLibrary || !require("node:path").isAbsolute(nativeLibrary) ||
      process.env.CLAUDE_WRAPPER_INIT_OWNER !== "bun") {
    fail();
  }
  // Native constructors must never own Bun's readiness acknowledgement. The
  // helper also supplies INIT_OWNER at exec time because Bun's environment map
  // and C environ are not guaranteed to synchronize after mutation.
  delete process.env.CLAUDE_WRAPPER_READY_FD;
  const native = require("bun:ffi").dlopen(nativeLibrary, {
    claude_wrapper_activate: { args: [], returns: "int" },
    claude_wrapper_self_test: { args: [], returns: "u32" },
    claude_wrapper_get_status: { args: ["ptr", "u64"], returns: "int" },
    claude_wrapper_clear_bootstrap: { args: [], returns: "int" },
  });
  const activation = native.symbols.claude_wrapper_activate();
  if (activation !== 0 || native.symbols.claude_wrapper_self_test() !== 224) {
    process.stderr.write(`identity-launch: native identity activation failed (${activation})\n`);
    fail();
  }
  const status = Buffer.alloc(160);
  if (native.symbols.claude_wrapper_get_status(status, 160n) !== 0) fail();
  const field = index => status.readBigUInt64LE(index * 8);
  if (field(0) !== 2n || field(1) !== 160n || field(2) !== 0n ||
      field(3) !== 224n || field(19) !== 1n ||
      (field(16) !== 0n && field(17) === 0n) ||
      [7, 12, 13, 14, 15, 18].some(index => field(index) !== 0n)) {
    fail();
  }
  Object.defineProperty(globalThis, Symbol.for("claude-wrapper.native-provider"), {
    value: native, writable: false, configurable: false, enumerable: false,
  });

  // Verify the supported client configuration before application code can send requests.
  // A shared or unexpected client fingerprint refuses startup instead of leaking it.
  const configDirectory = process.env.CLAUDE_CONFIG_DIR;
  if (!configDirectory) {
    fail();
  }
  const config = JSON.parse(fs.readFileSync(
    require("node:path").join(configDirectory, ".claude.json"), "utf8"));
  if (config.userID !== deviceId) {
    fail();
  }

  if (proxy !== undefined) {
    const url = new URL(proxy);
    if (url.protocol !== "http:" ||
        !["127.0.0.1", "[::1]"].includes(url.hostname) ||
        !url.port || url.port === "0" || url.pathname !== "/" || url.search || url.hash) {
      fail();
    }
    for (const key of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]) {
      process.env[key] = proxy;
    }
    process.env.NO_PROXY = "";
    process.env.no_proxy = "";
  }

  // Project/client settings are applied after preload. Keep Profile-owned values
  // consistent if those settings try to replace identity or network variables.
  const protectedKeys = [
    "TZ", "TZDIR", "TZFILE", "LANG", "LC_ALL", "LANGUAGE",
    "CLAUDE_CONFIG_DIR", "CFFIXED_USER_HOME", "__CF_USER_TEXT_ENCODING",
    "SSH_CLIENT", "SSH_CONNECTION", "REMOTE_ADDR", "REMOTE_HOST", "REMOTE_USER", "AppleLocale", "AppleLanguages",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy", "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING",
    "CLAUDE_CODE_ENABLE_TELEMETRY", "DO_NOT_TRACK",
  ];
  const apiBase = process.env.ANTHROPIC_BASE_URL;
  if (apiBase && new URL(apiBase).origin !== "https://api.anthropic.com") {
    const subscriptionOAuth = [
      "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR", "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    ];
    if (subscriptionOAuth.some(key => process.env[key])) fail();
    protectedKeys.push(...subscriptionOAuth);
  }
  const originalEnvironment = process.env;
  const protectedValues = new Map(protectedKeys.map(key => [key, originalEnvironment[key]]));

  function canLockOriginalEnvironment() {
    const key = "CLAUDE_WRAPPER_ENV_LOCK_CAPABILITY_PROBE";
    if (Object.hasOwn(originalEnvironment, key)) fail();
    try {
      Object.defineProperty(originalEnvironment, key, {
        value: "probe", writable: false, configurable: true, enumerable: true,
      });
    } catch {
      // Newer Bun environment objects reject non-writable descriptors.
      if (Object.hasOwn(originalEnvironment, key)) fail();
      return false;
    }
    try {
      const descriptor = Object.getOwnPropertyDescriptor(originalEnvironment, key);
      return descriptor?.value === "probe" && descriptor.writable === false &&
        descriptor.configurable === true &&
        Reflect.set(originalEnvironment, key, "changed") === false &&
        originalEnvironment[key] === "probe";
    } finally {
      if (!Reflect.deleteProperty(originalEnvironment, key)) fail();
    }
  }
  const originalEnvironmentLocked = canLockOriginalEnvironment();
  if (originalEnvironmentLocked) {
    // Lock the original object, so saved references and Bun's aliases cannot
    // bypass the process.env Proxy. Missing controlled names become non-enumerable
    // own properties with value undefined: hasOwn/`in` consequently change.
    for (const [key, value] of protectedValues) {
      const descriptor = Object.getOwnPropertyDescriptor(originalEnvironment, key);
      Object.defineProperty(originalEnvironment, key, {
        value, writable: false, configurable: false,
        enumerable: descriptor?.enumerable ?? false,
      });
    }
  } else {
    process.stderr.write("identity-launch: original environment aliases cannot be locked by this runtime; coverage is partial\n");
  }
  function checkChange(key, value) {
    if (protectedValues.has(key) && value !== protectedValues.get(key)) {
      process.stderr.write(`identity-launch: settings attempted to change Profile variable ${key}\n`);
      process.exit(126);
    }
  }
  const environment = new Proxy(originalEnvironment, {
    set(target, key, value) {
      // A SameValue assignment cannot alter a locked property and satisfies
      // Proxy invariants, including the undefined slots for missing names.
      if (originalEnvironmentLocked && protectedValues.has(key) &&
          Object.is(value, protectedValues.get(key))) return true;
      checkChange(key, String(value));
      return Reflect.set(target, key, value, target);
    },
    deleteProperty(target, key) {
      checkChange(key, undefined);
      return Reflect.deleteProperty(target, key);
    },
    defineProperty(target, key, descriptor) {
      if (protectedValues.has(key)) {
        if (!Object.hasOwn(descriptor, "value")) fail();
        checkChange(key, String(descriptor.value));
      }
      return Reflect.defineProperty(target, key, descriptor);
    },
  });

  if (previousOptions === undefined) {
    delete process.env.BUN_OPTIONS;
  } else {
    process.env.BUN_OPTIONS = previousOptions;
  }
  if (native.symbols.claude_wrapper_clear_bootstrap() !== 0) fail();
  for (const key of [
    "CLAUDE_WRAPPER_READY_FD",
    "CLAUDE_WRAPPER_PROXY_URL", "CLAUDE_WRAPPER_ORIGINAL_BUN_OPTIONS",
    "CLAUDE_WRAPPER_DEVICE_ID",
    "CLAUDE_WRAPPER_PRELOAD_FD",
    "CLAUDE_WRAPPER_NATIVE_LIBRARY", "CLAUDE_WRAPPER_INIT_OWNER",
  ]) {
    delete process.env[key];
  }
  Object.defineProperty(process, "env", { value: environment, writable: false, configurable: false });
  if (preload !== undefined) {
    if (!/^[0-9]+$/.test(preload) || Number(preload) < 3 || !Number.isSafeInteger(Number(preload))) {
      fail();
    }
    fs.closeSync(Number(preload));
  }
  if (ready !== undefined) {
    if (!/^[0-9]+$/.test(ready) || Number(ready) < 3 || !Number.isSafeInteger(Number(ready))) {
      fail();
    }
    if (!fs.fstatSync(Number(ready)).isFIFO()) fail();
    fs.writeSync(Number(ready), "1");
    fs.closeSync(Number(ready));
  }
} catch {
  fail();
}

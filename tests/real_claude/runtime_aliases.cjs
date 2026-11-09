"use strict";
// Diagnostic only: no host values are printed and application entry never runs.
const nativeEnvironment=process.env;
const proxy=new Proxy(nativeEnvironment,{});
process.env=proxy;
const result={bunVersion:process.versions.bun,
  bunEnvFollowsReplacement:Bun.env===proxy,
  metaEnvFollowsReplacement:import.meta?.env===proxy,
  bunEnvConfigurable:Object.getOwnPropertyDescriptor(Bun,"env").configurable};
process.env=nativeEnvironment;
const key="CLAUDE_WRAPPER_ENV_DESCRIPTOR_PROBE";
try {
  Object.defineProperty(nativeEnvironment,key,{value:"test",writable:false,configurable:false,enumerable:true});
  result.readonlyAccepted=true;
} catch(error) {
  result.readonlyAccepted=false;
  result.readonlyError=error.message;
}
try { delete nativeEnvironment[key]; } catch { /* Temporary process exits below. */ }
process.stdout.write(JSON.stringify(result)+"\n");
process.exit(0);

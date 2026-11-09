"use strict";
// Test-only preload; the production Bun integration owns readiness separately.
const assert=require("node:assert/strict");
const fs=require("node:fs");
const os=require("node:os");
const {dlopen,FFIType:T}=require("bun:ffi");
const names=["abi_version","struct_size","activation_error","self_test_mask","image_callbacks","images_examined","unsupported_images","parse_failures","slots_matched","stores_performed","slots_written","slots_already_bound","slots_failed","protection_failures","restoration_failures","verification_failures","main_slots_matched","main_slots_written","main_slots_failed","active"];
const path=process.env.CLAUDE_WRAPPER_NATIVE_LIBRARY;
const expectedHost=process.env.HOSTNAME;
const expectedUser=process.env.USER;
const marker=process.env.CLAUDE_WRAPPER_TEST_IO;
const refs={read:fs.readFileSync,write:fs.writeFileSync,open:fs.openSync,stat:fs.statSync,realpath:fs.realpathSync,bunFile:Bun.file,bunWrite:Bun.write};
const before={inode:fs.statSync(marker).ino,path:fs.realpathSync(marker)};
const direct=dlopen("/usr/lib/libSystem.B.dylib",{
 gethostname:{args:[T.ptr,T.u64],returns:T.i32},
 dlopen:{args:[T.ptr,T.i32],returns:T.ptr},
 getenv:{args:[T.ptr],returns:T.ptr},
});
const consumerSymbols={cw_consumer_probe:{args:[],returns:T.u32},cw_consumer_constructor:{args:[],returns:T.u32}};
const existing=dlopen(process.env.CLAUDE_WRAPPER_TEST_EXISTING,consumerSymbols);
// Owner=bun is a native startup snapshot, not a JS-only deletion of READY_FD.
assert.equal(process.env.CLAUDE_WRAPPER_INIT_OWNER,"bun");
assert.ok(direct.symbols.dlopen(Buffer.from(path+"\0"),2|8));
const library=dlopen(path,{
 claude_wrapper_activate:{args:[],returns:T.i32},
 claude_wrapper_self_test:{args:[],returns:T.u32},
 claude_wrapper_get_status:{args:[T.ptr,T.u64],returns:T.i32},
 claude_wrapper_clear_bootstrap:{args:[],returns:T.i32},
});
function status(){
 const buffer=Buffer.alloc(names.length*8);
 assert.equal(library.symbols.claude_wrapper_get_status(buffer,buffer.length),0);
 return Object.fromEntries(names.map((name,index)=>[name,Number(buffer.readBigUInt64LE(index*8))]));
}
const activation=library.symbols.claude_wrapper_activate();
if(activation!==0){process.stderr.write("NATIVE_ACTIVATION_STATUS "+JSON.stringify(status())+"\n");process.exit(126);}
assert.equal(library.symbols.claude_wrapper_self_test(),224);
assert.equal(existing.symbols.cw_consumer_probe(),224);
assert.equal(os.hostname(),expectedHost);
assert.equal(os.userInfo().username,expectedUser);
const first=status();
assert.equal(first.abi_version,2);assert.equal(first.struct_size,160);
assert.equal(first.active,1);assert.equal(first.self_test_mask,224);
assert.ok(first.slots_written>0);
assert.equal(first.slots_failed,0);assert.equal(first.restoration_failures,0);assert.equal(first.verification_failures,0);
assert.equal(first.stores_performed,first.slots_written);
assert.equal(library.symbols.claude_wrapper_activate(),0);
assert.equal(status().slots_written,first.slots_written);
assert.equal(library.symbols.claude_wrapper_clear_bootstrap(),0);
const later=dlopen(process.env.CLAUDE_WRAPPER_TEST_FUTURE,consumerSymbols);
assert.equal(later.symbols.cw_consumer_probe(),224);
assert.equal(later.symbols.cw_consumer_constructor(),224);
const raw=Buffer.alloc(256);
const code=direct.symbols.gethostname(raw,raw.length);
const directHostname=code===0?raw.subarray(0,raw.indexOf(0)).toString("utf8"):null;
assert.equal(directHostname,expectedHost);
const freshDirect=dlopen("/usr/lib/libSystem.B.dylib",{gethostname:{args:[T.ptr,T.u64],returns:T.i32}});
const freshRaw=Buffer.alloc(256),freshCode=freshDirect.symbols.gethostname(freshRaw,freshRaw.length);
assert.equal(freshCode===0?freshRaw.subarray(0,freshRaw.indexOf(0)).toString("utf8"):null,expectedHost);
assert.equal(library.symbols.claude_wrapper_clear_bootstrap(),0);
for(const key of ["CLAUDE_WRAPPER_NATIVE_LIBRARY","CLAUDE_WRAPPER_INIT_OWNER"])
 assert.equal(direct.symbols.getenv(Buffer.from(key+"\0")),null);
assert.equal(library.symbols.claude_wrapper_self_test(),224);
assert.equal(fs.readFileSync,refs.read);assert.equal(fs.writeFileSync,refs.write);assert.equal(fs.openSync,refs.open);assert.equal(fs.statSync,refs.stat);assert.equal(fs.realpathSync,refs.realpath);assert.equal(Bun.file,refs.bunFile);assert.equal(Bun.write,refs.bunWrite);
fs.writeFileSync(marker,"native official I/O\n");
assert.equal(fs.readFileSync(marker,"utf8"),"native official I/O\n");
assert.equal(fs.statSync(marker).ino,before.inode);assert.equal(fs.realpathSync(marker),before.path);
process.stderr.write("NATIVE_PRODUCTION_RESULT "+JSON.stringify({bun:process.versions.bun,status:status(),existingConsumer:true,futureConstructor:true,sameFileFunctionsAndInode:true,systemHostname:true,systemUser:true,bootstrapClearedInC:true})+"\n");

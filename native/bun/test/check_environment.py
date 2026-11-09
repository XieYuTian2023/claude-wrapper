#!/usr/bin/env python3
"""Check actual-client environment alias protection; exit 3 means unsupported."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[3]
client=Path(sys.argv[1]).resolve()
for component in ("macos", "egress"):
    subprocess.run(["make", "-C", str(ROOT/"native"/component)], capture_output=True, check=True)
with tempfile.TemporaryDirectory(prefix="wrapper-env-contract-", dir="/tmp") as temporary:
    work=Path(temporary)
    config=work/"config"
    home=work/"home"
    install=work/"installation with spaces : test"
    for directory in (config,home,install):
        directory.mkdir()
    (config/".claude.json").write_text(json.dumps({"userID":"a"*64}))
    for name in ("identity-launch","identity.cjs","libclaude-wrapper.dylib"):
        shutil.copy2(ROOT/"native/macos/build"/name, install/name)
    for name in ("environment-before.cjs","environment-after.cjs"):
        shutil.copy2(ROOT/"native/bun/test"/name, work/name)
    env={"PATH":"/usr/bin:/bin", "HOME":str(home), "CLAUDE_CONFIG_DIR":str(config),
        "CLAUDE_WRAPPER_DEVICE_ID":"a"*64,
        "CLAUDE_WRAPPER_PROXY_URL":"http://wrapper:environment-test@127.0.0.1:65000/",
        "TZ":"America/New_York", "LANG":"en_US.UTF-8", "LC_ALL":"en_US.UTF-8", "LANGUAGE":"en_US",
        "ANTHROPIC_API_KEY":"sk-ant-wrapper-contract-dummy",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC":"1", "DISABLE_TELEMETRY":"1",
        "DISABLE_ERROR_REPORTING":"1", "CLAUDE_CODE_ENABLE_TELEMETRY":"0", "DO_NOT_TRACK":"1",
        "BUN_OPTIONS":"--preload "+str(work/"environment-before.cjs")}
    result=subprocess.run([str(ROOT/"native/egress/build/socket-guard"),"--ipv4","65000",
        str(install/"identity-launch"),"--bun",str(client),"--help"],cwd=work,env=env,
        capture_output=True,text=True,timeout=15)
    if result.returncode==0:
        assert "BUN_ENV_ALIASES_LOCKED" in result.stderr, result.stderr
        print(result.stderr.strip())
    elif result.returncode==3 and "BUN_ENV_ALIAS_PROTECTION_UNAVAILABLE" in result.stderr:
        print(result.stderr.strip())
        print("UNSUPPORTED: original environment aliases remain writable; this check did not pass.")
    else:
        print(result.stderr,file=sys.stderr)
    sys.exit(result.returncode)

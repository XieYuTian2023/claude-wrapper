#!/usr/bin/env python3
"""Run bounded, reproducible real-client privacy regressions with dummy credentials."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys

from analyze import summarize

ROOT=Path(__file__).resolve().parents[2]
CAPTURE=Path(__file__).with_name("capture.py")


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--out",required=True,type=Path)
    p.add_argument("--wrapper",required=True,type=Path)
    p.add_argument("--probe-proxy",required=True)
    p.add_argument("--native-dir",type=Path,default=ROOT/"native/macos/build")
    p.add_argument("--socket-guard",type=Path,default=ROOT/"native/egress/build/socket-guard")
    p.add_argument("--old",required=True,type=Path)
    p.add_argument("--current",required=True,type=Path)
    p.add_argument("--reuse-captures",action="store_true",help="re-analyze an existing suite without starting clients")
    args=p.parse_args()
    out=args.out.resolve()
    out.mkdir(parents=True,exist_ok=args.reuse_captures)
    jobs=[]
    def add(name,client,extra,wrapped=False,expected=None):
        command=[sys.executable,str(CAPTURE),"--out",str(out/name),"--timezone","Asia/Shanghai",
            "--claude",str(client.resolve()),"--native-dir",str(args.native_dir.resolve()),
            "--socket-guard",str(args.socket_guard.resolve()),*extra]
        if wrapped:
            command += ["--wrapper",str(args.wrapper.resolve()),"--probe-proxy",args.probe_proxy,
                "--disable-nonessential"]
        jobs.append((name,command,expected or {}))

    hosts=[("neither","api.audit.test","'"),("known","api.audit.cn","’"),
        ("keyword","deepseek.audit.test","ʼ"),("both","deepseek.audit.cn","ʹ")]
    for label,host,apostrophe in hosts:
        add("old-"+label,args.old,["--base-host",host],expected={"apostrophe":apostrophe,"separator":"/"})
    add("old-us",args.old,["--timezone","America/Los_Angeles","--base-host","api.audit.test"],
        expected={"apostrophe":"'","separator":"-"})
    for label,client in [("old",args.old),("current",args.current)]:
        add(label+"-wrapped",client,["--base-host","api.audit.test"],True,
            {"apostrophe":"'","separator":"-","device":"a"*64,"no_telemetry":True})
        for key,value in [("TZ","Asia/Shanghai"),("HOSTNAME","unexpected-host"),
            ("LC_ALL","zh_CN.UTF-8"),("NO_PROXY","*"),
            ("ANTHROPIC_BASE_URL","https://deepseek.audit.cn"),
            ("CLAUDE_CONFIG_DIR",str(out/"unexpected-config")),
            ("DISABLE_TELEMETRY","0")]:
            add(label+"-reject-"+key.lower(),client,["--project-env",key+"="+value],True,{"reject_key":key})
    add("current-wrapped-interactive",args.current,["--interactive"],True,
        {"apostrophe":"'","separator":"-","device":"a"*64,"no_telemetry":True})

    def run(job):
        name,command,expected=job
        if not args.reuse_captures:
            executed=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=65)
            if executed.returncode:
                return {"name":name,"passed":False,"error":executed.stderr[-1500:]}
        directory=out/name
        result=json.loads((directory/"result.json").read_text())
        summary=summarize(directory)
        failures=[]
        setting_outcome=None
        if "reject_key" in expected:
            rejected=result["exit"]==126 and summary["model_requests"]==0 and expected["reject_key"] in result["stderr"]
            # Newer Claude versions ignore CLAUDE_CONFIG_DIR in settings.json.
            # Verify that behavior instead of requiring a write that never occurs.
            ignored=expected["reject_key"]=="CLAUDE_CONFIG_DIR" and result["exit"]==0 and summary["model_requests"]>0 \
                and summary["device_ids"]==["a"*64] and not (out/"unexpected-config").exists()
            if not rejected and not ignored:
                failures.append("controlled project setting was not rejected before model request")
            setting_outcome="rejected before model request" if rejected else "client ignored setting; Profile identity preserved" if ignored else "failed"
        else:
            if result["exit"]!=0 or summary["model_requests"]<1:
                failures.append("actual client did not complete a fixture response")
            for line in summary["date_lines"]:
                if line[5]!=expected["apostrophe"] or line[20]!=expected["separator"]:
                    failures.append("unexpected date bytes: "+repr(line))
            if not summary["date_lines"]:
                failures.append("date line missing")
            if "device" in expected and summary["device_ids"]!=[expected["device"]]:
                failures.append("device identity mismatch")
            if expected.get("no_telemetry") and any("/api/eval/" in path or "/api/event_logging/" in path for path in summary["requests"]):
                failures.append("nonessential traffic observed")
        if summary["unexpected_auth"]:
            failures.append("unexpected credentials")
        return {**summary,"passed":not failures,"failures":failures,"setting_outcome":setting_outcome}
    with ThreadPoolExecutor(max_workers=3) as pool:
        results=list(pool.map(run,jobs))
    (out/"summary.json").write_text(json.dumps(results,ensure_ascii=False,indent=2)+"\n")
    for item in results:
        print(("PASS " if item["passed"] else "FAIL ")+item["name"]+" "+str(item.get("failures",item.get("error",""))))
    print(f"{sum(item['passed'] for item in results)}/{len(results)} passed; {out/'summary.json'}")
    return 0 if all(item["passed"] for item in results) else 1


if __name__=="__main__":
    sys.exit(main())

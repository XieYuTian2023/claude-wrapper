#!/usr/bin/env python3
"""Summarize fixture-only captures, including JSON embedded in metadata fields."""
import argparse
import base64
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def summarize(directory):
    capture=directory/"requests.json"
    records=json.loads(capture.read_text())
    result=json.loads((directory/"result.json").read_text())
    requests=[r for r in records if r.get("event")=="request"]
    devices=set()
    dates=set()
    timezones=set()
    field_paths=set()
    decoded_count=0

    def visit(value,path=""):
        nonlocal decoded_count
        if isinstance(value,dict):
            for key,item in value.items():
                next_path=path+"."+key
                if re.search(r"device|host.?name|user.?name|locale|time.?zone|platform|arch|runtime|entrypoint",key,re.I):
                    field_paths.add(next_path)
                if key in ("device_id","deviceID") and isinstance(item,str):
                    devices.add(item)
                if isinstance(item,str) and key in ("user_id","additional_metadata","process"):
                    decoded=None
                    try:
                        decoded=json.loads(item)
                    except (ValueError,TypeError):
                        try:
                            decoded=json.loads(base64.b64decode(item,validate=True))
                        except (ValueError,TypeError,UnicodeError):
                            pass
                    if decoded is not None:
                        decoded_count+=1
                        visit(decoded,next_path+"[decoded]")
                visit(item,next_path)
        elif isinstance(value,list):
            for item in value:
                visit(item,path+"[]")
        elif isinstance(value,str):
            dates.update(re.findall(r"Today[^\n]{0,8}s date is \d{4}[-/]\d{2}[-/]\d{2}\.",value))
            timezones.update(re.findall(r"(?:Asia|America|US)/[A-Za-z_/-]+",value))

    for request in requests:
        visit(request.get("body"),request["path"].split("?")[0])
    return {
        "name":directory.name,"exit":result["exit"],"seconds":result["seconds"],
        "capture_sha256":hashlib.sha256(capture.read_bytes()).hexdigest(),
        "requests":dict(Counter(r["path"].split("?")[0] for r in requests)),
        "model_requests":sum(r["path"].startswith("/v1/messages?") or r["path"]=="/v1/messages" for r in requests),
        "device_ids":sorted(devices),"date_lines":sorted(dates),
        "date_codepoints":{line:[f"U+{ord(c):04X}" for c in line] for line in sorted(dates)},
        "timezone_strings":sorted(timezones),"decoded_json_fields":decoded_count,
        "identity_field_paths":sorted(field_paths),
        "unexpected_auth":sum(bool(r.get("unexpected_auth")) for r in requests),
        "tls_errors":sum(r.get("event")=="tls-error" for r in records),
    }


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("directories",nargs="+",type=Path)
    parser.add_argument("--out",type=Path)
    args=parser.parse_args()
    summaries=[summarize(directory) for directory in args.directories]
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(summaries,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps([{k:v for k,v in item.items() if k in ("name","exit","model_requests","device_ids","date_lines","timezone_strings","unexpected_auth","tls_errors")} for item in summaries],ensure_ascii=False,indent=2))


if __name__=="__main__":
    main()

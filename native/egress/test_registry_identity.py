#!/usr/bin/env python3
"""Check real registry/NVRAM identity sources; never print their values."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess

HERE=Path(__file__).resolve().parent
IDENTITY_KEYS={"IOPlatformUUID","IOPlatformSerialNumber","IOMACAddress","IO80211BSSID",
    "IO80211SSID","IO80211CountryCode","CountryCode","DisplaySerialNumber","FirmwareSerialNumber",
    "Serial","Serial Number","SerialNumber","ThunderboltUUID","USB Serial Number",
    "kUSBSerialNumberString","serial-number","UUID","NamespaceUUID","VolGroupUUID",
    "boot-uuid-media","previous-system-uuid","Domain UUID","BootSessionUUID","SleepWakeUUID",
    "IOSkywalkNexusUUID","IODisplayEDID","prev-lang:kbd"}


def inspect(command):
    result=subprocess.run(command,capture_output=True,timeout=30)
    if result.returncode:
        raise RuntimeError(f"registry inspection failed with exit {result.returncode}")
    counts=Counter()
    ordinary_models=[]
    def visit(value):
        if isinstance(value,dict):
            for key in IDENTITY_KEYS:
                if key in value: counts[key]+=1
            if value.get("IOObjectClass")=="IOPlatformExpertDevice" and "model" in value:
                ordinary_models.append(value["model"])
            visit(value.get("IORegistryEntryChildren",[]))
        elif isinstance(value,list):
            for entry in value:visit(entry)
    visit(plistlib.loads(result.stdout))
    return dict(sorted(counts.items())),ordinary_models


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--guard",type=Path,default=HERE/"build/socket-guard")
    parser.add_argument("--out",type=Path)
    args=parser.parse_args()
    guard=args.guard.resolve(strict=True)
    target=["/usr/sbin/ioreg","-a","-l","-p","IOService"]
    baseline,models=inspect(target)
    flags=["--ipv4","--identity-guard","--hide-interfaces","--hide-account-records","--identity-files","65000"]
    protected,protected_models=inspect([str(guard),*flags,*target])
    result={"guard_sha256":hashlib.sha256(guard.read_bytes()).hexdigest(),"arguments":flags,
        "baseline_property_counts":baseline,"guarded_property_counts":protected,
        "not_exercised":sorted(IDENTITY_KEYS-set(baseline)),
        "observed_identity_properties_absent":all(protected.get(key,0)==0 for key in baseline),
        "ordinary_platform_model_unchanged":bool(models) and models==protected_models}
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
    assert baseline.get("IOPlatformUUID",0)>0 and baseline.get("IOMACAddress",0)>0, "baseline did not exercise core sources"
    assert result["observed_identity_properties_absent"] and result["ordinary_platform_model_unchanged"]


if __name__=="__main__":
    main()

#!/usr/bin/env python3
"""Read-only checks of real network/location identity files under the real guard.

Never opens a system file for writing and never records file contents. Ordinary
I/O is exercised only on a temporary file owned by this test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SOURCES = [
    "/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist",
    "/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
    "/Library/Preferences/SystemConfiguration/com.apple.smb.server.plist",
    "/Library/Preferences/SystemConfiguration/com.apple.network.identification.plist",
    "/Library/Preferences/com.apple.wifi.known-networks.plist",
    "/Library/Preferences/com.apple.timezone.auto.plist",
    "/Library/Preferences/com.apple.locationd.plist",
    "/etc/resolv.conf", "/private/etc/resolv.conf",
    "/var/run/resolv.conf", "/private/var/run/resolv.conf",
    "/private/var/run/utmpx", "/var/run/utmpx",
    "/private/var/log/lastlog", "/var/log/lastlog",
    "/private/var/log/wtmp", "/var/log/wtmp",
]


def probe(marker):
    results = {}
    for path in SOURCES:
        try:
            with open(path, "rb") as stream:
                stream.read(1)
            results[path] = {"readable": True}
        except OSError as error:
            results[path] = {"readable": False, "errno": error.errno}
    before = os.stat(marker)
    with open(marker, "ab") as stream:
        stream.write(b"ordinary native file\n")
    after = os.stat(marker)
    with open(marker, "rb") as stream:
        correct = stream.read().endswith(b"ordinary native file\n")
    return {"sources": results, "ordinaryIo": {
        "sameInode": before.st_ino == after.st_ino,
        "sameOwner": before.st_uid == after.st_uid,
        "samePath": os.path.realpath(marker) == marker,
        "readWrite": correct,
    }}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guard", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--probe")
    args = parser.parse_args()
    if args.probe:
        print(json.dumps(probe(args.probe)))
        return
    if not args.guard or not args.out:
        parser.error("--guard and --out are required")
    guard = args.guard.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="identity-source-readonly-") as temp:
        home = Path(temp).resolve()
        marker = home / "ordinary.txt"
        marker.write_bytes(b"owned fixture\n")
        env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TZ": "America/New_York",
               "USER": "profile-reader", "LOGNAME": "profile-reader",
               "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"}
        command = [sys.executable, str(Path(__file__).resolve()), "--probe", str(marker)]
        baseline = json.loads(subprocess.check_output(command, env=env, text=True, timeout=20))
        guarded = json.loads(subprocess.check_output([
            str(guard), "--ipv4", "--identity-guard", "--hide-interfaces",
            "--hide-account-records", "--identity-files", "65000", *command,
        ], env=env, text=True, timeout=20))
        observed = [path for path in SOURCES if baseline["sources"][path]["readable"]]
        assert observed, "No real readable source was observed; coverage is untested."
        failures = [path for path in SOURCES if guarded["sources"][path]["readable"]]
        assert not failures, {"unexpectedReadableSources": failures}
        assert all(guarded["sources"][path].get("errno") in (1, 13) for path in observed)
        assert all(guarded["ordinaryIo"].values()), guarded["ordinaryIo"]
        result = {"guardSha256": hashlib.sha256(guard.read_bytes()).hexdigest(),
                  "passed": True, "realReadableSourcesBlocked": len(observed),
                  "baseline": baseline, "guarded": guarded,
                  "systemWritesAttempted": False,
                  "scope": "Only observed readable sources establish a before/after denial; absent or OS-denied sources do not."}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({key: result[key] for key in ("passed", "realReadableSourcesBlocked", "guardSha256", "systemWritesAttempted")}))


if __name__ == "__main__":
    main()

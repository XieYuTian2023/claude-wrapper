#!/usr/bin/env python3
"""Measure cached native file I/O with startup and GeoIP excluded.

Five alternating rounds compare bare, full guard, and full guard plus the
production native provider. Every process runs at most 100,000 measured
open/fstat/read64/close cycles on one temporary owned cache file. This is a
bounded local microbenchmark, never a zero-overhead guarantee.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
MODES = ("bare", "full_guard", "full_guard_native")


def machine_info():
    values = {}
    for key in ("hw.model", "machdep.cpu.brand_string", "hw.physicalcpu", "hw.logicalcpu", "hw.memsize"):
        result = subprocess.run(["/usr/sbin/sysctl", "-n", key], capture_output=True, text=True, check=True)
        values[key] = result.stdout.strip()
    return {"os": platform.system(), "architecture": platform.machine(), "macos": platform.mac_ver()[0],
        "kernel_release": platform.release(), "hardware": values}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guard", required=True, type=Path)
    parser.add_argument("--native-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--prepare-only", action="store_true", help="compile and freeze components without measuring")
    args = parser.parse_args()
    if not 1 <= args.iterations <= 100000:
        parser.error("iterations must be from 1 to 100000")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = HERE / "benchmark_file_io.c"
    shutil.copy2(source, out / source.name)
    shutil.copy2(Path(__file__), out / Path(__file__).name)
    binary = out / "file-io-benchmark"
    subprocess.run(["/usr/bin/clang", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-mmacosx-version-min=11.0", str(source), "-o", str(binary)], check=True, capture_output=True)
    components = out / "components"
    components.mkdir(exist_ok=True)
    paths = {"socket-guard": args.guard.resolve(),
        "identity-launch": args.native_dir.resolve() / "identity-launch",
        "libclaude-wrapper.dylib": args.native_dir.resolve() / "libclaude-wrapper.dylib"}
    fingerprints = {}
    for name, path in paths.items():
        shutil.copy2(path, components / name)
        fingerprints[name] = hashlib.sha256((components / name).read_bytes()).hexdigest()
    metadata = {"created_at_utc": datetime.now(timezone.utc).isoformat(), "machine": machine_info(),
        "components_sha256": fingerprints,
        "benchmark_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "benchmark_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "iterations_per_process": args.iterations, "rounds": 5,
        "operation": "open(O_RDONLY|O_CLOEXEC), fstat, read 64 bytes, close",
        "timing": "CLOCK_MONOTONIC_RAW inside the target loop; process/provider startup and GeoIP excluded",
        "scope": "one temporary owned cached file; no writes to system files; no guarantee of zero overhead"}
    (out / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
    if args.prepare_only:
        print("Prepared benchmark components; no measurements run")
        return 0

    env = {key: value for key, value in os.environ.items() if not key.startswith(("DYLD_", "CLAUDE_WRAPPER_", "CW_IO_BENCH_"))}
    env.update({"TZ": "America/Los_Angeles", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8"})
    for key in ("TZFILE", "TZDIR"):
        env.pop(key, None)
    guard = [str(components / "socket-guard"), "--ipv4", "--identity-guard", "--hide-interfaces",
        "--identity-files", "65000"]
    samples = []
    with tempfile.TemporaryDirectory(prefix="cached-io-benchmark-", dir="/tmp") as temporary:
        cache = Path(temporary).resolve() / "owned-cache-file"
        payload = bytes(range(256)) * 16
        cache.write_bytes(payload)
        cache.chmod(0o600)
        assert cache.read_bytes() == payload
        info = cache.stat()
        for round_index in range(5):
            order = MODES if round_index % 2 == 0 else tuple(reversed(MODES))
            for mode in order:
                command = [str(binary), str(cache), str(args.iterations)]
                child_env = dict(env)
                if mode == "full_guard":
                    command = [*guard, *command]
                elif mode == "full_guard_native":
                    child_env["CW_IO_BENCH_NATIVE_EXPECTED"] = "1"
                    command = [*guard, str(components / "identity-launch"), *command]
                started = time.monotonic()
                result = subprocess.run(command, env=child_env, capture_output=True, text=True, timeout=30)
                if result.returncode:
                    raise RuntimeError(mode + " benchmark target failed: " + result.stderr[:1200])
                sample = json.loads(result.stdout)
                sample.update({"round": round_index + 1, "mode": mode, "execution_order": list(order),
                    "process_wall_seconds_including_startup": time.monotonic() - started})
                samples.append(sample)
                print(mode + " round " + str(round_index + 1) + ": " + format(sample["ns_per_iteration"], ".2f") + " ns/op", flush=True)
                (out / "samples.json").write_text(json.dumps(samples, indent=2) + "\n")
        assert cache.read_bytes() == payload and cache.stat().st_ino == info.st_ino and cache.stat().st_uid == info.st_uid
    medians = {mode: statistics.median(sample["ns_per_iteration"] for sample in samples if sample["mode"] == mode) for mode in MODES}
    summary = {"median_ns_per_iteration": medians,
        "relative_to_bare_percent": {mode: (value / medians["bare"] - 1) * 100 for mode, value in medians.items()},
        "all_samples": len(samples), "owned_file_contents_inode_owner_unchanged": True,
        "limitations": "Five local cached-read samples per mode; scheduling, cache and power-state noise remain. Does not measure startup, real Claude workloads, cold I/O, large reads, or file writes. No zero-overhead guarantee."}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

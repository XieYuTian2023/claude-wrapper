#!/usr/bin/env python3
"""Collect the bounded 2026-11-08 run, preserving failures/unsupported outcomes.

This does not run clients or imply that any missing test passed.
"""
import hashlib
import json
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(relative):
    return json.loads((ROOT / relative).read_text())


def main():
    suite_path = "target/compat/audit/release-sandbox-suite-20261108/summary.json"
    suite = read(suite_path)
    assert len(suite) == 22 and all(row["passed"] for row in suite)
    native_path = "target/compat/late-native-production/results.json"
    native = read(native_path)
    assert len(native) == 2 and all(row["exit"] == 0 and row["status"]["main_slots_written"] > 0
                                  and row["status"]["self_test_mask"] == 255 for row in native)
    registry_path = "target/compat/identity-sources/2026-11-08-registry-release.json"
    registry = read(registry_path)
    assert registry["observed_identity_properties_absent"] and registry["ordinary_platform_model_unchanged"]
    files_path = "target/compat/identity-sources/2026-11-08-network-files-release.json"
    files = read(files_path)
    boundaries_path = "target/compat/identity-sources/2026-11-08-production-file-boundaries-fixed.json"
    boundaries = read(boundaries_path)
    assert files["passed"] and boundaries["all_passed"]
    assert files["guardSha256"] == registry["guard_sha256"] == boundaries["guard_sha256"]
    aliases_path = "target/compat/audit/release-environment-aliases-20261108.json"
    aliases = read(aliases_path)
    assert [row["outcome"] for row in aliases] == ["passed", "unsupported"]
    unit_path = "target/compat/audit/release-unit-validation-20261108/result.json"
    unit = read(unit_path)
    assert unit["cargoTestExit"] == unit["cargoFmtExit"] == 0
    benchmark = "target/compat/benchmarks/2026-11-08-full-identity-io/summary.json"
    development_path = "target/compat/identity-sources/2026-11-08-development-tools.json"
    development = read(development_path)
    assert development["all_passed"] and development["guard_sha256"] == registry["guard_sha256"]
    source_probe = "target/compat/identity-sources/2026-11-08-production-sources-release.json"
    tools = {}
    sources = [suite_path, native_path, registry_path, files_path, boundaries_path, aliases_path, unit_path, benchmark,
               development_path, source_probe]
    official = {}
    for version, label in (("2.1.169", "old"), ("2.1.319", "current")):
        relative = f"target/compat/audit/release-tools-{label}-20261108/tool-scenario.json"
        report = read(relative)
        assert report["passed"] and len(report["checks"]) == 32 and all(report["checks"].values())
        assert report["runtime_assets"]["socket_guard"]["sha256"] == registry["guard_sha256"]
        for asset in report["runtime_assets"].values():
            assert digest(Path(asset["path"])) == asset["sha256"]
        sources.append(relative)
        tools[version] = {"passed": True, "checks": report["checks"], "stages": report["stages"],
                          "runtime_sha256": {name: row["sha256"] for name, row in report["runtime_assets"].items()},
                          "source": relative,
                          "child_native_identity": "account/hostname unavailable; USERNAME unavailable; USER and LOGNAME match Profile"}
        binary = ROOT / f"target/compat/claude-code-{version}/package/claude"
        signature = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(binary)], capture_output=True)
        assert signature.returncode == 0
        official[version] = {"sha256": digest(binary), "strictSignatureValid": True}
        assert official[version]["sha256"] == tools[version]["runtime_sha256"]["official_claude"]
    source_files = []
    for folder in ("src", "native", "tests", "scripts", "launcher"):
        source_files.extend(path for path in (ROOT / folder).rglob("*") if path.is_file()
                            and not {"build", "__pycache__"}.intersection(path.relative_to(ROOT).parts))
    source_files.extend(ROOT / path for path in ("Cargo.toml", "Cargo.lock", "README.md", "docs/identity-sandbox-design.md", "reports/2026-11-08-identity-sandbox-audit.md"))
    evidence = {
        "date": "2026-11-08",
        "machine": {"architecture": platform.machine(), "macOS": platform.mac_ver()[0]},
        "method": "Actual official signed executables and genuine client tools; local TLS model fixture and dummy credentials. Only GeoIP probe forwarded. No live account/model validation.",
        "official_clients": official,
        "release_suite": {"passed": 22, "total": 22, "cases": [
            {key: row[key] for key in ("name", "passed", "exit", "capture_sha256", "model_requests", "date_codepoints", "device_ids", "setting_outcome")}
            for row in suite]},
        "actual_tools": tools,
        "native_binding": native,
        "registry": registry,
        "network_identity_files": files,
        "identity_file_boundaries": boundaries,
        "environment_aliases": [{key: row[key] for key in ("version", "exit", "outcome")} for row in aliases],
        "rust_validation": unit,
        "file_io_benchmark": read(benchmark),
        "development_tools": development,
        "production_source_probes": read(source_probe),
        "earlier_failures_retained": {
            "directory_symlink_collision": "target/compat/identity-sources/2026-11-08-production-file-boundaries.json",
            "initial_tool_url_oracle": "target/compat/audit/actual-tools-final-20261108-summary.json",
            "initial_registry_nvram_gap": "target/compat/identity-sources/2026-11-08-iokit-inventory.json",
        },
        "limits": [
            "Bun 1.4.4 original environment aliases cannot be locked; this is unsupported, not a passing result.",
            "Direct native pointers/syscalls bypass import rebinding; only enumerated kernel sources are guarded.",
            "Real files, paths, UID/ownership, account identity, unknown sources/caches and external brokers remain boundaries.",
            "OAuth/keychain/browser login and live model/authentication were not tested.",
            "GeoIP samples do not prove per-destination or continuous US egress.",
            "Apple Silicon only cross-built; cached C I/O microbenchmark is not a zero-overhead guarantee.",
        ],
        "evidence_sha256": {path: digest(ROOT / path) for path in sources},
        "source_sha256": {str(path.relative_to(ROOT)): digest(path) for path in sorted(source_files)},
    }
    target = ROOT / "reports/evidence/2026-11-08-summary.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"output": str(target), "bytes": target.stat().st_size, "sha256": digest(target),
                      "releaseScenarios": 22, "toolChecksEach": 32, "fileBoundaries": len(boundaries["results"]),
                      "registryKindsObserved": len(registry["baseline_property_counts"])}))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Check production identity-file rules using temporary identity replicas only.

Never writes a real system preference. The guard binary is copied before the
matrix so every case runs exactly the same build. No host identity values or
real preference filenames are printed.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

FAKE_UUID = "00000000-0000-4000-8000-000000000001"
CASES = (
    "plain", "spaces", "double_quote", "backslash", "mixed_quote_backslash", "unicode", "home_symlink",
    "identity_file_symlink", "encoding_file_symlink", "byhost_global_symlink",
    "preferences_directory_symlink", "byhost_directory_symlink", "library_directory_symlink", "control_character", "oversized_home",
)


def denied(operation):
    try:
        result = operation()
        if isinstance(result, int):
            os.close(result)
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES), "unexpected denial code"
        return
    raise AssertionError("identity operation was allowed")


def worker(specification):
    spec = json.loads(Path(specification).read_text())
    root = Path(spec["temporary_root"]).resolve()
    project = Path(spec["project_file"])
    assert project.resolve().is_relative_to(root), "fixture escaped temporary root"
    Path(spec["marker"]).write_text("started")
    with project.open("r+b") as stream:
        assert stream.read() == b"ordinary project file", "ordinary project data changed"
        info = os.fstat(stream.fileno())
        assert info.st_ino == spec["project_inode"] and info.st_uid == spec["project_uid"], "ordinary file metadata changed"
        os.pwrite(stream.fileno(), b"ordinary", 0)
    assert project.name in os.listdir(project.parent), "ordinary project enumeration changed"
    for name in spec.get("extra_project_files", []):
        assert Path(name).read_bytes() == b"ordinary canonical project file", "canonical project file changed"
    for name in spec.get("extra_project_directories", []):
        assert "source.txt" in os.listdir(name), "canonical project directory enumeration changed"
    known = Path(spec["known_byhost_file"])
    assert known.read_bytes() == b"ordinary known per-host preference", "known non-identity preference changed"
    protected = spec["protected"]
    for name in spec["identities"]:
        path = Path(name)
        assert path.parent.resolve().is_relative_to(root), "identity write fixture escaped temporary root"
        if not protected:
            assert path.read_bytes() == b"temporary identity data", "baseline identity fixture is not readable"
            fd = os.open(path, os.O_WRONLY)
            os.close(fd)
            continue
        denied(path.read_bytes)
        denied(lambda path=path: os.open(path, os.O_WRONLY | os.O_TRUNC))
        denied(lambda path=path: os.chmod(path, 0o640))
        scratch = project.parent / "atomic-replacement"
        scratch.write_bytes(b"temporary replacement data")
        try:
            denied(lambda path=path: os.replace(scratch, path))
        finally:
            if scratch.exists():
                scratch.unlink()
        denied(path.unlink)
    if protected:
        denied(lambda: os.open(spec["byhost_directory"], os.O_RDONLY))
    else:
        assert os.listdir(spec["byhost_directory"]), "baseline ByHost enumeration unavailable"
    return {"ok": True, "ordinary_project_verified": True, "known_byhost_file_read": True,
        "identity_sources_checked": len(spec["identities"]), "protected": protected}


def seed_home(home):
    preferences = home / "Library/Preferences"
    byhost = preferences / "ByHost"
    byhost.mkdir(parents=True)
    identities = [preferences / ".GlobalPreferences.plist", preferences / ".GlobalPreferences_m.plist",
        home / ".CFUserTextEncoding", byhost / (".GlobalPreferences." + FAKE_UUID + ".plist")]
    for path in identities:
        path.write_bytes(b"temporary identity data")
    known = byhost / ("com.apple.fixture.nonidentity." + FAKE_UUID + ".plist")
    known.write_bytes(b"ordinary known per-host preference")
    return identities, byhost, known


def run_case(name, directory, guard, source):
    case = directory / name
    case.mkdir()
    work = case / "project"
    work.mkdir()
    project = work / "source.txt"
    project.write_bytes(b"ordinary project file")
    names = {"spaces": "home with spaces", "double_quote": 'home"quoted', "backslash": "home\\backslash",
        "mixed_quote_backslash": 'home"\\mixed', "unicode": "home-é-路径", "control_character": "home\ncontrol"}
    home = case / names.get(name, "home")
    identities, byhost, known = seed_home(home)
    reject_expected = name in ("identity_file_symlink", "encoding_file_symlink", "byhost_global_symlink",
        "preferences_directory_symlink", "byhost_directory_symlink", "library_directory_symlink", "control_character", "oversized_home")
    project_files = []
    project_directories = []
    if name == "home_symlink":
        alias = case / "home-alias"
        alias.symlink_to(home, target_is_directory=True)
        identities = [alias / path.relative_to(home) for path in identities]
        byhost = alias / byhost.relative_to(home)
        known = alias / known.relative_to(home)
        home = alias
    elif name in ("identity_file_symlink", "encoding_file_symlink", "byhost_global_symlink"):
        index = {"identity_file_symlink": 0, "encoding_file_symlink": 2, "byhost_global_symlink": 3}[name]
        identities[index].unlink()
        identities[index].symlink_to(project)
    elif name == "preferences_directory_symlink":
        preferences = home / "Library/Preferences"
        project_preferences = work / "ordinary-preferences-fixture"
        preferences.rename(project_preferences)
        preferences.symlink_to(project_preferences, target_is_directory=True)
        canonical = project_preferences / ".GlobalPreferences.plist"
        canonical.write_bytes(b"ordinary canonical project file")
        project_files.append(str(canonical))
    elif name == "library_directory_symlink":
        library = home / "Library"
        project_library = work / "ordinary-library-fixture"
        library.rename(project_library)
        library.symlink_to(project_library, target_is_directory=True)
        canonical = project_library / "Preferences/.GlobalPreferences.plist"
        canonical.write_bytes(b"ordinary canonical project file")
        project_files.append(str(canonical))
    elif name == "byhost_directory_symlink":
        saved = home / "saved-identity-namespace"
        byhost.rename(saved)
        byhost.symlink_to(work, target_is_directory=True)
        project_directories.append(str(work))
        identities = identities[:3]
        known = work / "known-preference"
        known.write_bytes(b"ordinary known per-host preference")
    elif name == "oversized_home":
        home = case / ("oversized" * 200)

    marker = work / "target-started"
    info = project.stat()
    spec = {"temporary_root": str(directory), "project_file": str(project), "project_inode": info.st_ino,
        "project_uid": info.st_uid, "identities": [str(path) for path in identities],
        "byhost_directory": str(byhost), "known_byhost_file": str(known), "marker": str(marker),
        "extra_project_files": project_files, "extra_project_directories": project_directories, "protected": False}
    specification = case / "specification.json"
    specification.write_text(json.dumps(spec))
    env = {key: value for key, value in os.environ.items() if not key.startswith(("DYLD_", "CLAUDE_WRAPPER_"))}
    env.update({"HOME": str(home), "CLAUDE_WRAPPER_ACCOUNT_HOME": str(home), "PYTHONDONTWRITEBYTECODE": "1"})
    command = [sys.executable, str(source), "--worker", str(specification)]
    if not reject_expected and not project_files and not project_directories:
        baseline = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
        assert baseline.returncode == 0, "baseline fixture failed: " + name
        marker.unlink()
    spec["protected"] = True
    specification.write_text(json.dumps(spec))
    before = (project.read_bytes(), project.stat().st_ino, project.stat().st_uid)
    alias_files_before = {name: (Path(name).read_bytes(), Path(name).stat().st_ino, Path(name).stat().st_uid) for name in project_files}
    alias_directories_before = {name: (sorted(os.listdir(name)), Path(name).stat().st_ino, Path(name).stat().st_uid) for name in project_directories}
    protected_command = [str(guard), "--ipv4", "--identity-guard", "--hide-interfaces", "--identity-files", "65000", *command]
    completed = subprocess.run(protected_command, env=env, capture_output=True, text=True, timeout=15)
    after = (project.read_bytes(), project.stat().st_ino, project.stat().st_uid)
    unchanged = before == after
    alias_targets_unchanged = all((Path(name).read_bytes(), Path(name).stat().st_ino, Path(name).stat().st_uid) == state for name, state in alias_files_before.items()) \
        and all((sorted(os.listdir(name)), Path(name).stat().st_ino, Path(name).stat().st_uid) == state for name, state in alias_directories_before.items())
    refused = completed.returncode == 125 and not marker.exists()
    if reject_expected:
        passed = refused and unchanged and alias_targets_unchanged
        outcome = "refused before target" if refused else "target was not safely refused"
    elif project_files or project_directories:
        passed = unchanged and (refused or completed.returncode == 0)
        outcome = "ambiguous alias refused" if refused else "alias accepted without project interference" if completed.returncode == 0 else "alias interfered with ordinary project access"
    else:
        passed = unchanged and completed.returncode == 0
        outcome = "identity sources isolated; ordinary paths retained" if passed else "guard or path checks failed"
    return {"case": name, "passed": passed, "exit": completed.returncode, "target_started": marker.exists(),
        "ordinary_project_unchanged": unchanged, "outcome": outcome,
        "ordinary_project_alias_targets_unchanged": alias_targets_unchanged,
        "worker_result": completed.stdout.strip()[:500] if marker.exists() else None}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--guard", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--case", action="append", choices=CASES)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        try:
            print(json.dumps(worker(args.worker)))
            return 0
        except Exception as error:
            print(json.dumps({"ok": False, "error_type": type(error).__name__,
                "check": str(error) if isinstance(error, AssertionError) else "fixture operation failed"}))
            return 1
    if not args.guard:
        parser.error("--guard is required")
    original = args.guard.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="identity-boundaries-", dir="/tmp") as temporary:
        directory = Path(temporary).resolve()
        frozen = directory / "socket-guard"
        shutil.copy2(original, frozen)
        checksum = hashlib.sha256(frozen.read_bytes()).hexdigest()
        results = [run_case(name, directory, frozen, Path(__file__).resolve()) for name in args.case or CASES]
    report = {"guard_sha256": checksum, "results": results, "all_passed": all(result["passed"] for result in results),
        "writes": "temporary replicas only; no real system preference was written"}
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    for result in results:
        print(("PASS " if result["passed"] else "FAIL ") + result["case"] + ": " + result["outcome"])
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Exercise real local development tools under the complete production guard.

Every write, including Git commits, is confined to an owned temporary HOME and
worktree. Git's system/global configuration, attributes and default templates
are disabled. This is a guard/tool regression, not an official Claude test.
The guard is frozen before either run and host identity values are not printed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


FLAGS = ("--ipv4", "--identity-guard", "--hide-interfaces", "--hide-account-records", "--identity-files")


def worker(specification):
    spec = json.loads(Path(specification).read_text())
    work = Path(spec["work"])
    root = work.parent.resolve()
    assert work.resolve().is_relative_to(root)
    checks = []

    def command(name, arguments, validate=lambda value: True):
        try:
            completed = subprocess.run(arguments, cwd=work, capture_output=True, text=True, timeout=30)
            passed = completed.returncode == 0 and validate(completed.stdout)
            result = {"check": name, "passed": passed, "exit": completed.returncode,
                "stdout": completed.stdout.replace(str(root), "<TEMP_ROOT>"),
                "stderr": completed.stderr.replace(str(root), "<TEMP_ROOT>")}
        except (OSError, subprocess.TimeoutExpired) as error:
            result = {"check": name, "passed": False, "error_type": type(error).__name__}
        checks.append(result)
        return result["passed"]

    def file_check(name, callback):
        try:
            callback()
            checks.append({"check": name, "passed": True})
        except Exception as error:
            checks.append({"check": name, "passed": False, "error_type": type(error).__name__})

    source = work / "source.py"

    def python_io():
        source.write_text("print('local fixture')\n")
        info = source.stat()
        assert info.st_uid == spec["uid"]
        with source.open("r+b") as stream:
            assert stream.read() == b"print('local fixture')\n"
            assert os.fstat(stream.fileno()).st_ino == info.st_ino
            os.pwrite(stream.fileno(), b"print", 0)
        assert source.stat().st_ino == info.st_ino

    file_check("python_real_file_read_write_inode_owner", python_io)
    command("python_spawn", [sys.executable, "-c", "print('python-child-ok')"],
        lambda value: value.strip() == "python-child-ok")

    git = spec["git"]
    command("git_init", [git, "init", "--initial-branch=main", "--template=" + spec["empty"], "."])
    for key, value in (("user.name", "Fixture Developer"), ("user.email", "fixture@example.invalid"),
            ("commit.gpgsign", "false"), ("core.hooksPath", spec["empty"])):
        command("git_config_" + key, [git, "config", "--local", key, value])
    command("git_status_untracked", [git, "status", "--porcelain=v1"], lambda value: "?? source.py" in value)
    command("git_add", [git, "add", "--", "source.py"])
    command("git_diff_staged", [git, "diff", "--cached", "--", "source.py"],
        lambda value: "+print('local fixture')" in value)
    command("git_commit", [git, "commit", "-m", "local fixture commit"])
    command("git_log", [git, "log", "-1", "--format=%H%n%an%n%ae%n%s"],
        lambda value: "\nFixture Developer\nfixture@example.invalid\nlocal fixture commit\n" in value)
    command("git_status_clean", [git, "status", "--porcelain=v1"], lambda value: not value.strip())
    source.write_text("print('edited fixture')\n")
    command("git_diff_worktree", [git, "diff", "--", "source.py"],
        lambda value: "-print('local fixture')" in value and "+print('edited fixture')" in value)
    command("git_status_modified", [git, "status", "--porcelain=v1"], lambda value: " M source.py" in value)

    node_source = r"""
const fs = require('fs');
const cp = require('child_process');
const assert = require('assert');
fs.writeFileSync('node-source.txt', 'node local fixture');
const before = fs.statSync('node-source.txt');
assert.strictEqual(before.uid, Number(process.env.FIXTURE_UID));
const fd = fs.openSync('node-source.txt', 'r+');
const data = Buffer.alloc(18);
assert.strictEqual(fs.readSync(fd, data, 0, data.length, 0), data.length);
assert.strictEqual(data.toString(), 'node local fixture');
assert.strictEqual(fs.fstatSync(fd).ino, before.ino);
fs.writeSync(fd, Buffer.from('node'), 0, 4, 0);
fs.closeSync(fd);
assert.strictEqual(fs.statSync('node-source.txt').ino, before.ino);
const child = cp.spawnSync(process.env.FIXTURE_PYTHON, ['-c', "print('node-child-ok')"], {encoding:'utf8'});
assert.strictEqual(child.status, 0);
assert.strictEqual(child.stdout.trim(), 'node-child-ok');
console.log(JSON.stringify({read_write_inode_owner:true, spawn:true}));
"""
    command("node_real_file_read_write_inode_owner_and_spawn", [spec["node"], "-e", node_source],
        lambda value: json.loads(value) == {"read_write_inode_owner": True, "spawn": True})
    command("uname_system", [spec["uname"], "-s"], lambda value: value.strip() == "Darwin")
    command("uname_machine", [spec["uname"], "-m"], lambda value: value.strip() in ("x86_64", "arm64"))
    return {"all_passed": all(result["passed"] for result in checks), "checks": checks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guard", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker)))
        return 0
    if not args.guard or not args.out:
        parser.error("--guard and --out are required")
    tools = {name: shutil.which(name) for name in ("git", "node", "uname")}
    if not all(tools.values()):
        parser.error("git, node and uname must be available")
    with tempfile.TemporaryDirectory(prefix="development-tools-", dir="/tmp") as temporary:
        directory = Path(temporary).resolve()
        frozen = directory / "socket-guard"
        shutil.copy2(args.guard.resolve(strict=True), frozen)
        checksum = hashlib.sha256(frozen.read_bytes()).hexdigest()
        results = []
        for guarded in (False, True):
            case = directory / ("guarded" if guarded else "bare")
            home, work, empty = (case / name for name in ("home", "work", "empty"))
            (home / "Library/Preferences/ByHost").mkdir(parents=True)
            work.mkdir()
            empty.mkdir()
            specification = case / "specification.json"
            specification.write_text(json.dumps({"work": str(work), "empty": str(empty),
                "uid": os.getuid(), **tools}))
            env = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": str(case),
                "USER": "fixture-developer", "LOGNAME": "fixture-developer", "SHELL": "/bin/sh",
                "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8", "TZ": "America/Los_Angeles",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_ATTR_NOSYSTEM": "1", "GIT_TEMPLATE_DIR": str(empty), "GIT_TERMINAL_PROMPT": "0",
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                "FIXTURE_UID": str(os.getuid()), "FIXTURE_PYTHON": sys.executable,
                "CLAUDE_WRAPPER_ACCOUNT_HOME": str(home)}
            command = [sys.executable, str(Path(__file__).resolve()), "--worker", str(specification)]
            if guarded:
                command = [str(frozen), *FLAGS, "65000", *command]
            completed = subprocess.run(command, env=env, cwd=work, capture_output=True, text=True, timeout=120)
            try:
                detail = json.loads(completed.stdout)
            except json.JSONDecodeError:
                detail = {"all_passed": False, "worker_output_valid": False}
            results.append({"mode": "full_production_guard" if guarded else "bare_baseline",
                "exit": completed.returncode, "stderr": completed.stderr.replace(str(directory), "<TEMP_ROOT>"), **detail})
    report = {"kind": "actual production guard development-tool regression; not official Claude tool test",
        "guard_sha256": checksum, "guard_flags": list(FLAGS), "tools": tools,
        "isolation": "owned temporary HOME/worktree; Git system/global config and attributes disabled; empty templates/hooks; no network",
        "all_passed": all(result["exit"] == 0 and result["all_passed"] for result in results), "results": results}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"all_passed": report["all_passed"], "modes": [{"mode": item["mode"],
        "passed": sum(check["passed"] for check in item.get("checks", [])),
        "total": len(item.get("checks", []))} for item in results]}))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

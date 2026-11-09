#!/usr/bin/env python3
"""Exercise an npm shell launcher using owned temporary native stubs only.

Never invokes a real wrapper, client, network endpoint, global npm installation,
or user configuration. Platform simulation changes only the uname executable
path in a temporary launcher copy when the production launcher uses an absolute
uname path; that distinction is recorded in the evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


def stub(path, architecture):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/python3\nimport json,os,sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['FIXTURE_RESULT']).write_text(json.dumps({"
        "'pid':os.getpid(),'arguments':sys.argv[1:],'architecture':" + repr(architecture) + "}))\n"
        "raise SystemExit(37)\n")
    path.chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--x64", type=Path, required=True, help="x64 native executable relative to package root")
    parser.add_argument("--arm64", type=Path, required=True, help="arm64 executable relative to package root")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    for relative in (args.x64, args.arm64):
        if relative.is_absolute() or ".." in relative.parts:
            parser.error("native stub paths must remain inside the temporary package")
    original = args.launcher.resolve(strict=True)
    source = original.read_text()
    results = []
    results.append({"case": "production_launcher_executable", "passed": os.access(original, os.X_OK)})
    syntax = subprocess.run(["/bin/sh", "-n", str(original)], capture_output=True, text=True)
    results.append({"case": "production_posix_shell_syntax", "passed": syntax.returncode == 0})
    with tempfile.TemporaryDirectory(prefix="wrapper-npm-launcher-", dir="/tmp") as temporary:
        directory = Path(temporary).resolve()
        prefix = directory / "prefix with spaces 'quote' $literal \\backslash"
        package = prefix / "lib/node_modules/fixture-package"
        launcher = package / "bin/claude-wrapper"
        launcher.parent.mkdir(parents=True)
        shutil.copy2(original, launcher)
        native = {"x86_64": package / args.x64, "arm64": package / args.arm64}
        for architecture, path in native.items():
            stub(path, architecture)
        global_bin = prefix / "bin"
        global_bin.mkdir()
        global_link = global_bin / "claude-wrapper"
        global_link.symlink_to(os.path.relpath(launcher, global_bin))
        aliases = directory / "aliases with spaces"
        aliases.mkdir()
        relative_link = aliases / "relative-entry"
        relative_link.symlink_to(os.path.relpath(global_link, aliases))
        absolute_link = aliases / "absolute-entry"
        absolute_link.symlink_to(relative_link)
        work = directory / "work"
        work.mkdir()
        marker = directory / "result.json"
        injected = directory / "injection-would-create-this"
        arguments = ["", "space value", "single'quote", 'double"quote', "$HOME", "\\backslash\\",
            "$(touch " + str(injected) + ")", "`touch " + str(injected) + "`",
            "; touch " + str(injected), "one\nnewline", "trailing\n", "--leading-flag", "路径-é"]
        environment = {"PATH": str(global_bin) + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(directory / "home"), "FIXTURE_RESULT": str(marker), "CDPATH": str(aliases)}
        Path(environment["HOME"]).mkdir()
        actual_architecture = platform.machine()

        def check(name, command, expected_architecture=None, refusal=False, env=None, invocation_kind="unmodified_launcher"):
            marker.unlink(missing_ok=True)
            try:
                process = subprocess.Popen(command + arguments, cwd=work, env=env or environment,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = process.communicate(timeout=10)
                detail = json.loads(marker.read_text()) if marker.exists() else None
                if refusal:
                    passed = process.returncode != 0 and detail is None and not injected.exists()
                else:
                    passed = process.returncode == 37 and detail is not None \
                        and detail["arguments"] == arguments and detail["pid"] == process.pid \
                        and detail["architecture"] == expected_architecture and not injected.exists()
                results.append({"case": name, "passed": passed, "invocation_kind": invocation_kind,
                    "exit": process.returncode, "argv_exact": detail["arguments"] == arguments if detail else None,
                    "same_pid_proves_exec": detail["pid"] == process.pid if detail else None,
                    "selected_architecture": detail["architecture"] if detail else None,
                    "injection_marker_absent": not injected.exists(),
                    "stdout": stdout.replace(str(directory), "<TEMP>"),
                    "stderr": stderr.replace(str(directory), "<TEMP>")})
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
                if isinstance(error, subprocess.TimeoutExpired):
                    process.kill()
                    process.communicate()
                results.append({"case": name, "passed": False, "error_type": type(error).__name__})

        check("direct_package_path", [str(launcher)], actual_architecture)
        check("relative_npm_bin_symlink", [str(global_link)], actual_architecture)
        check("relative_multihop_symlink", [str(relative_link)], actual_architecture)
        check("absolute_then_relative_symlink_chain", [str(absolute_link)], actual_architecture)
        check("path_lookup_global_bin", ["claude-wrapper"], actual_architecture)
        saved = native[actual_architecture].read_bytes()
        native[actual_architecture].unlink()
        check("missing_runtime_refused", [str(global_link)], refusal=True)
        native[actual_architecture].write_bytes(saved)
        native[actual_architecture].chmod(0o644)
        check("nonexecutable_runtime_refused", [str(global_link)], refusal=True)
        native[actual_architecture].chmod(0o755)

        # A control-character install path may be refused or supported, but a
        # truncated path must never silently select a different sibling runtime.
        controls = directory / "control-path-fixture"
        for name, architecture in (("package\n", actual_architecture), ("package", "decoy")):
            destination = controls / name
            entry = destination / "bin/claude-wrapper"
            entry.parent.mkdir(parents=True)
            entry.write_text(source)
            for relative in (args.x64, args.arm64):
                stub(destination / relative, architecture)
        marker.unlink(missing_ok=True)
        control = subprocess.run(["/bin/sh", str(controls / "package\n/bin/claude-wrapper")],
            cwd=work, env=environment, capture_output=True, text=True, timeout=10)
        detail = json.loads(marker.read_text()) if marker.exists() else None
        results.append({"case": "trailing_lf_package_does_not_select_decoy", "invocation_kind": "unmodified_launcher_explicit_shell",
            "passed": (control.returncode != 0 and detail is None) or
                (control.returncode == 37 and detail is not None and detail["architecture"] == actual_architecture),
            "exit": control.returncode, "refused": control.returncode != 0 and detail is None,
            "selected_decoy": detail is not None and detail["architecture"] == "decoy"})

        fake_uname = directory / "fixture-uname"
        fake_uname.write_text("#!/usr/bin/python3\nimport os,sys\n"
            "print(os.environ['FIXTURE_SYSTEM' if sys.argv[-1]=='-s' else 'FIXTURE_ARCH'])\n")
        fake_uname.chmod(0o755)
        if "/usr/bin/uname" in source:
            launcher.write_text(source.replace("/usr/bin/uname", str(fake_uname)))
            simulation_kind = "temporary_copy_only_uname_path_substituted"
        elif "uname" in source:
            fake_bin = directory / "fake-bin"
            fake_bin.mkdir()
            (fake_bin / "uname").symlink_to(fake_uname)
            environment["PATH"] = str(fake_bin) + ":" + environment["PATH"]
            simulation_kind = "unmodified_launcher_path_uname_shim"
        else:
            simulation_kind = None
            results.append({"case": "platform_simulation_available", "passed": False})
        if simulation_kind:
            for system, architecture, expected in (("Darwin", "x86_64", "x86_64"), ("Darwin", "arm64", "arm64"),
                    ("Linux", "x86_64", None), ("Darwin", "unknown-test-cpu", None)):
                simulated = dict(environment, FIXTURE_SYSTEM=system, FIXTURE_ARCH=architecture)
                check("simulated_" + system + "_" + architecture, [str(global_link)], expected,
                    refusal=expected is None, env=simulated, invocation_kind=simulation_kind)
    report = {"launcher_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
        "all_passed": all(result["passed"] for result in results), "results": results,
        "scope": "owned temporary package/stubs only; no actual native wrapper/client/global installation/network",
        "native_relative_paths": {"x86_64": str(args.x64), "arm64": str(args.arm64)}}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"all_passed": report["all_passed"], "passed": sum(item["passed"] for item in results),
        "total": len(results)}))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

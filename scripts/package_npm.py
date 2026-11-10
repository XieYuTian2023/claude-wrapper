#!/usr/bin/env python3
"""Build an npm tarball from precompiled native artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ("claude-wrapper", "identity-launch", "socket-guard", "identity.cjs", "libclaude-wrapper.dylib")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "dist/npm")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    metadata = json.loads((ROOT / "npm/package.json").read_text())
    assert not metadata.get("private") and not metadata.get("scripts")
    assert not metadata.get("dependencies") and not metadata.get("optionalDependencies")
    assert metadata["os"] == ["darwin"] and metadata["cpu"] == ["x64", "arm64"]
    runtime = {}
    with tempfile.TemporaryDirectory(prefix="wrapper-npm-pack-") as temp:
        temporary = Path(temp)
        stage = temporary / "package"
        stage.mkdir()
        for relative in ("package.json", "README.md", "bin/claude-wrapper"):
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / "npm" / relative, destination)
        (stage / "bin/claude-wrapper").chmod(0o755)
        shutil.copy2(ROOT / "LICENSE", stage / "LICENSE")
        shutil.copy2(ROOT / "native/macos/LICENSE.fishhook", stage / "LICENSE.fishhook")
        for arch, npm_arch, rust, native_subdir in (
            ("x86_64", "x64", ROOT / "target/release/claude-wrapper", ""),
            ("arm64", "arm64", ROOT / "target/aarch64-apple-darwin/release/claude-wrapper", "arm64"),
        ):
            native = ROOT / "native/macos/build" / native_subdir
            egress = ROOT / "native/egress/build" / native_subdir
            destination = stage / "native" / f"darwin-{npm_arch}"
            destination.mkdir(parents=True)
            hashes = {}
            for name in ASSETS:
                selected = {"claude-wrapper": rust, "socket-guard": egress / name}.get(name, native / name)
                if name != "identity.cjs":
                    actual = subprocess.check_output(["/usr/bin/lipo", "-archs", str(selected)], text=True).strip()
                    assert actual == arch, (name, actual, arch)
                shutil.copy2(selected, destination / name)
                hashes[name] = sha(destination / name)
            runtime[npm_arch] = {"files": hashes,
                                 "validation": "Intel build; installation/TUI results are recorded separately" if arch == "x86_64" else "Cross-built only; not executed on Apple Silicon"}
        (stage / "runtime-sha256.json").write_text(json.dumps(runtime, indent=2) + "\n")
        env = os.environ.copy()
        for name in list(env):
            if name.lower().startswith("npm_config_"):
                env.pop(name)
        user_config, global_config = temporary / "user.npmrc", temporary / "global.npmrc"
        user_config.write_text("")
        global_config.write_text("")
        env.update({"npm_config_cache": str(temporary / "cache"), "npm_config_userconfig": str(user_config),
                    "npm_config_globalconfig": str(global_config), "npm_config_offline": "true",
                    "npm_config_audit": "false", "npm_config_fund": "false"})
        result = subprocess.run(["npm", "pack", "--json", "--ignore-scripts", "--pack-destination", str(out)],
                                cwd=stage, env=env, capture_output=True, text=True, timeout=60, check=True)
        packed = json.loads(result.stdout)[0]
        archive = out / packed["filename"]
        expected = {"package/package.json", "package/README.md", "package/LICENSE", "package/LICENSE.fishhook",
                    "package/runtime-sha256.json", "package/bin/claude-wrapper"}
        expected.update(f"package/native/darwin-{arch}/{name}" for arch in ("x64", "arm64") for name in ASSETS)
        with tarfile.open(archive, "r:gz") as stream:
            members = stream.getmembers()
            assert {member.name for member in members} == expected
            assert all(member.isfile() and not Path(member.name).is_absolute() and ".." not in Path(member.name).parts for member in members)
            for member in members:
                path = stage / Path(member.name).relative_to("package")
                assert hashlib.sha256(stream.extractfile(member).read()).hexdigest() == sha(path)
            assert stream.getmember("package/bin/claude-wrapper").mode & 0o111
            for arch in ("x64", "arm64"):
                for name in ("claude-wrapper", "identity-launch", "socket-guard"):
                    assert stream.getmember(f"package/native/darwin-{arch}/{name}").mode & 0o111
        proof = {"package": metadata["name"], "version": metadata["version"], "archive": archive.name,
                 "sha256": sha(archive), "bytes": archive.stat().st_size, "npmIntegrity": packed["integrity"],
                 "fileCount": len(expected), "archivePathsAndHashesVerified": True, "runtime": runtime,
                 "installScripts": False, "npmDependencies": [], "published": False,
                 "source": {path: sha(ROOT / path) for path in ("Cargo.toml", "Cargo.lock", "src/main.rs", "src/profile.rs", "src/exit_pin.rs", "src/exit_regions.rs", "src/iso3166.tab", "src/journal.rs", "src/tui.rs", "src/proxy.rs", "src/relay/mod.rs", "src/relay/activity.rs", "src/relay/vpn.rs", "src/relay/vpn_dns.rs", "native/macos/identity.m", "native/macos/rebind.c", "native/bun/identity.cjs", "native/egress/socket_guard.c", "native/egress/identity_files.h", "npm/bin/claude-wrapper", "npm/package.json")}}
        (out / "manifest.json").write_text(json.dumps(proof, indent=2) + "\n")
        print(json.dumps({key: proof[key] for key in ("archive", "sha256", "bytes", "fileCount", "published")}))


if __name__ == "__main__":
    main()

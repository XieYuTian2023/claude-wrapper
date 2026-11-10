#!/usr/bin/env python3
"""Package already-built macOS artifacts and verify every archive member.

No downloads, global installs, source rewriting or client redistribution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    version = json.loads((ROOT / "npm/package.json").read_text())["version"]
    report = ROOT / "reports/2026-11-08-identity-sandbox-audit.md"
    evidence = ROOT / "reports/evidence/2026-11-08-summary.json"
    index = {}
    for arch, rust, native, guard, validation in (
        ("x86_64", "target/release", "native/macos/build", "native/egress/build", "Intel build. AUDIT.md describes earlier, version-specific observations."),
        ("arm64", "target/aarch64-apple-darwin/release", "native/macos/build/arm64", "native/egress/build/arm64", "Cross-built only; no Apple Silicon runtime validation"),
    ):
        name = f"claude-wrapper-macos-{arch}"
        destination = out / name
        destination.mkdir(exist_ok=True)
        sources = {
            "claude-wrapper": ROOT / rust / "claude-wrapper",
            "identity-launch": ROOT / native / "identity-launch",
            "libclaude-wrapper.dylib": ROOT / native / "libclaude-wrapper.dylib",
            "identity.cjs": ROOT / native / "identity.cjs",
            "socket-guard": ROOT / guard / "socket-guard",
            "LICENSE": ROOT / "LICENSE",
            "LICENSE.fishhook": ROOT / "native/macos/LICENSE.fishhook",
            "Launch Claude.command": ROOT / "launcher/Launch Claude.command",
            "AUDIT.md": report,
            "evidence/2026-11-08-summary.json": evidence,
        }
        for item in ("claude-wrapper", "identity-launch", "libclaude-wrapper.dylib", "socket-guard"):
            actual = subprocess.check_output(["/usr/bin/lipo", "-archs", str(sources[item])], text=True).strip()
            if actual != arch:
                raise RuntimeError(f"Wrong architecture for {item}: {actual}")
        for relative, source in sources.items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        readme = f"""Claude Wrapper {version} — macOS {arch}

Validation: {validation}

Keep all runtime files together. This package does not contain Claude Code.
Use an installed official native executable, or pass --target /absolute/path/to/claude.

Create a Profile using an already connected US VPN:
  ./claude-wrapper profile create west-dev --vpn-interface auto
Or use an HTTP(S) proxy instead of --vpn-interface:
  ./claude-wrapper profile create west-dev --proxy http://127.0.0.1:1082

  ./claude-wrapper doctor west-dev --target /absolute/path/to/claude
  cd /absolute/path/to/your/project
  /absolute/path/to/this/package/claude-wrapper run west-dev --target /absolute/path/to/claude

Double-click Launch Claude.command to select an existing Profile and project.
It finds claude in PATH. From a terminal you can instead set absolute paths:
  CLAUDE_WRAPPER_CLIENT=/absolute/path/to/claude './Launch Claude.command' west-dev /absolute/project
Optional CLAUDE_WRAPPER_PROFILES_DIR overrides the Profile directory.
The folder picker GUI itself has not been tested; argument/selection behavior has stub tests.

Profiles use separate official Claude configuration directories. Login is separate;
the same service account remains linkable. Configuration changes apply on next launch.
Deleting a Profile retains client login/history and reserves that retained state name.

Read AUDIT.md before relying on the protection. It covers specific observed sources,
not all future APIs or fingerprints. Bun 1.4.4 raw environment alias locking is
unsupported and reports partial coverage. Real paths, file contents and ownership
remain unchanged. Network probes cannot prove every destination's egress country.
Browser login, local listeners and Unix sockets may be restricted.
No VM, administrator permission or system security changes are required.

SHA256SUMS.json covers the shipped files except itself. The packager verifies
archive paths and all content hashes. Preserve LICENSE and LICENSE.fishhook on redistribution.
"""
        (destination / "README.txt").write_text(readme)
        names = sorted([*sources, "README.txt"])
        checksums = {relative: sha(destination / relative) for relative in names}
        (destination / "SHA256SUMS.json").write_text(json.dumps(checksums, indent=2) + "\n")
        archive = out / (name + ".tar.gz")
        with tempfile.NamedTemporaryFile(dir=out, suffix=".tar.gz") as temp:
            with tarfile.open(temp.name, "w:gz") as stream:
                for relative in [*names, "SHA256SUMS.json"]:
                    stream.add(destination / relative, arcname=f"{name}/{relative}", recursive=False)
            with tarfile.open(temp.name, "r:gz") as stream:
                members = stream.getmembers()
                expected = {f"{name}/{relative}" for relative in [*names, "SHA256SUMS.json"]}
                assert {member.name for member in members} == expected
                assert all(member.isfile() and not Path(member.name).is_absolute() and ".." not in Path(member.name).parts for member in members)
                for relative, digest in checksums.items():
                    data = stream.extractfile(f"{name}/{relative}").read()
                    assert hashlib.sha256(data).hexdigest() == digest
                for relative in ("claude-wrapper", "identity-launch", "socket-guard", "Launch Claude.command"):
                    assert stream.getmember(f"{name}/{relative}").mode & 0o111
            shutil.copyfile(temp.name, archive)
        index[arch] = {"archive": archive.name, "sha256": sha(archive), "bytes": archive.stat().st_size,
                       "validation": validation, "files": checksums, "archiveVerified": True}
    (out / "manifest.json").write_text(json.dumps(index, indent=2) + "\n")
    print(json.dumps({arch: {key: entry[key] for key in ("archive", "sha256", "bytes", "archiveVerified")} for arch, entry in index.items()}, indent=2))


if __name__ == "__main__":
    main()

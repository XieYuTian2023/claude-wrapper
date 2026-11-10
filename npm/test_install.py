#!/usr/bin/env python3
"""Real offline npm install/update/uninstall in an owned temporary prefix.

Does not alter the user's npm prefix, profiles, shell config, account or Claude.
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


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--tui-out", type=Path, help="also run the actual PTY suite through the installed npm bin")
    args = parser.parse_args()
    archive = args.archive.resolve(strict=True)
    npm = shutil.which("npm")
    assert npm, "npm is required"
    checks = {}
    with tempfile.TemporaryDirectory(prefix="wrapper npm install test ") as temp:
        root = Path(temp).resolve()
        prefix = root / "prefix with spaces"
        home = root / "home"
        home.mkdir()
        configs = root / "configs"
        configs.mkdir()
        (configs / "user").write_text("")
        (configs / "global").write_text("")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home),
               "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
               "npm_config_cache": str(root / "cache"),
               "npm_config_userconfig": str(configs / "user"),
               "npm_config_globalconfig": str(configs / "global"),
               "npm_config_offline": "true", "npm_config_audit": "false", "npm_config_fund": "false"}
        def run(command):
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
            assert result.returncode == 0, {"command": command[:2], "exit": result.returncode, "stderr": result.stderr}
            return result
        install = [npm, "install", "--global", "--prefix", str(prefix), "--ignore-scripts", "--offline", "--no-audit", "--no-fund", str(archive)]
        run(install)
        checks["actual_offline_install"] = True
        binary = prefix / "bin/claude-wrapper"
        shortcut = prefix / "bin/cw"
        assert binary.is_symlink() and os.access(binary, os.X_OK)
        assert shortcut.is_symlink() and shortcut.resolve() == binary.resolve()
        checks["npm_global_bin_symlink"] = True
        result = subprocess.run([str(shortcut), "--version"], env=env, capture_output=True,
                                text=True, timeout=15)
        assert result.returncode != 0 and "还没有配置" in result.stderr and not result.stdout
        checks["short_command_uses_direct_start"] = True
        package = prefix / "lib/node_modules/claude-wrapper-local"
        metadata = json.loads((package / "package.json").read_text())
        assert metadata["private"] is True and not metadata.get("scripts") and not metadata.get("dependencies")
        checks["no_lifecycle_scripts_or_dependencies"] = True
        runtime = json.loads((package / "runtime-sha256.json").read_text())
        for arch, row in runtime.items():
            for name, expected in row["files"].items():
                assert digest(package / "native" / f"darwin-{arch}" / name) == expected
        checks["installed_assets_match_all_architecture_hashes"] = True
        help_text = run([str(binary), "--help"]).stdout
        assert "profile" in help_text and "ui" in help_text and "doctor" in help_text
        checks["installed_help_has_tui_and_existing_commands"] = True
        version = run([str(binary), "--version"]).stdout.strip()
        checks["installed_native_version"] = version.startswith("claude-wrapper ")
        profiles = root / "profiles"
        cli = [str(binary), "--profiles-dir", str(profiles)]
        run([*cli, "profile", "create", "npm-fixture"])
        default_profile = (profiles / "npm-fixture.toml").read_text()
        assert all(setting in default_profile for setting in (
            'vpn_interface = "auto"', 'expected_exit_ip = "auto"',
            'exit_check_interval_seconds = "auto"',
        ))
        checks["new_profile_uses_automatic_defaults"] = True
        invalid = subprocess.run(
            [*cli, "profile", "create", "bad-region", "--vpn-interface", "auto",
             "--expected-exit-country", "ZZ"],
            env=env, capture_output=True, text=True, timeout=15,
        )
        assert invalid.returncode != 0 and "recognized two-letter region code" in invalid.stderr
        checks["unknown_exit_region_rejected"] = True
        invalid_interval = subprocess.run(
            [*cli, "profile", "create", "bad-interval", "--vpn-interface", "auto",
             "--exit-check-interval", "4"],
            env=env, capture_output=True, text=True, timeout=15,
        )
        assert invalid_interval.returncode != 0 and "between 5 and 3600" in invalid_interval.stderr
        checks["out_of_range_exit_interval_rejected"] = True
        assert run([*cli, "profile", "list"]).stdout.strip() == "npm-fixture"
        checks["installed_profile_create_and_list"] = True
        run([*cli, "profile", "copy", "npm-fixture", "npm-copy"])
        run([*cli, "profile", "create", "region-only", "--proxy", "http://127.0.0.1:8080",
             "--region-only", "--exit-check-interval", "45"])
        region_only = (profiles / "region-only.toml").read_text()
        assert 'expected_exit_ip' not in region_only and 'vpn_interface' not in region_only
        assert 'exit_check_interval_seconds = 45' in region_only
        checks["explicit_proxy_region_and_interval_override_automatic_defaults"] = True
        a = (profiles / "npm-fixture.toml").read_text()
        b = (profiles / "npm-copy.toml").read_text()
        import re
        ids = [re.search(r'^device_id = "([0-9a-f]{64})"$', value, re.M).group(1) for value in (a, b)]
        assert ids[0] != ids[1]
        checks["installed_copy_creates_distinct_device_id"] = True
        # Static preflight only: no exit probe, model, authentication or session.
        client = shutil.which("claude")
        if client:
            plan = run([*cli, "run", "region-only", "--target", client, "--dry-run"])
            assert "America/Los_Angeles" in plan.stdout
            assert "exit-interval  45s" in plan.stdout
            adaptive = run([*cli, "run", "npm-fixture", "--target", client, "--dry-run",
                            "--exit-check-interval", "auto"])
            assert "exit-interval  auto (2–30s)" in adaptive.stdout
            checks["adaptive_exit_interval_supported"] = True
            assert "hostname" not in plan.stdout and "username" not in plan.stdout
            checks["installed_sibling_assets_static_preflight"] = True
            dummy = "wrapper-test-subscription-token-not-a-credential"
            credential_env = {**env, "CLAUDE_CODE_OAUTH_TOKEN": dummy}
            for variable in ("CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
                             "CLAUDE_CODE_OAUTH_REFRESH_TOKEN"):
                custom = subprocess.run(
                    [*cli, "run", "npm-fixture", "--target", client, "--dry-run",
                     "--api-base-url", "https://gateway.invalid"],
                    env={**env, variable: dummy}, capture_output=True, text=True, timeout=15,
                )
                assert custom.returncode != 0 and "subscription OAuth credential" in custom.stderr
                assert not custom.stdout and dummy not in custom.stderr
            official = subprocess.run(
                [*cli, "run", "npm-fixture", "--target", client, "--dry-run",
                 "--api-base-url", "https://api.anthropic.com"],
                env=credential_env, capture_output=True, text=True, timeout=15,
            )
            assert official.returncode == 0 and dummy not in official.stdout + official.stderr
            checks["explicit_oauth_cannot_route_to_custom_api"] = True
        else:
            checks["installed_sibling_assets_static_preflight"] = "not exercised: no installed Claude"
        state = profiles / "clients/npm-fixture/.claude.json"
        state.parent.mkdir(parents=True)
        marker = '{"fixture":"preserve during uninstall"}\n'
        state.write_text(marker)
        run(install)
        assert (profiles / "npm-fixture.toml").read_text() == a and state.read_text() == marker
        checks["reinstall_preserves_profile_and_client_state"] = True
        if args.tui_out:
            driver = Path(__file__).resolve().parents[1] / "tests/tui/pty_ui.py"
            completed = subprocess.run([sys.executable, str(driver), "--binary", str(binary),
                                        "--out", str(args.tui_out.resolve())], capture_output=True,
                                       text=True, timeout=180)
            assert completed.returncode == 0, {"ptyExit": completed.returncode, "stdout": completed.stdout[-3000:], "stderr": completed.stderr[-2000:]}
            checks["installed_tui_real_pty_suite"] = True
        run([npm, "uninstall", "--global", "--prefix", str(prefix), "--ignore-scripts", "--offline", "--no-audit", "--no-fund", "claude-wrapper-local"])
        assert not binary.exists() and not binary.is_symlink() and not package.exists()
        assert not shortcut.exists() and not shortcut.is_symlink()
        assert (profiles / "npm-fixture.toml").read_text() == a and state.read_text() == marker
        checks["actual_uninstall_removes_only_package"] = True
        assert all(value is True or isinstance(value, str) for value in checks.values())
        result = {"passed": True, "checks": checks, "archiveSha256": digest(archive),
                  "version": version, "scope": "Real npm install/reinstall/uninstall, Intel native commands, isolated temporary prefix and HOME; no live account, model or network probe."}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"passed": True, "checks": len(checks), "archiveSha256": result["archiveSha256"]}))


if __name__ == "__main__":
    main()

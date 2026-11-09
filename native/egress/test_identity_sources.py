#!/usr/bin/env python3
"""Probe real macOS identity sources without exposing their values.

Only per-run keyed digests pass through child stdout. The public report contains
availability and comparisons, never those digests or real identity strings.
This is an exploratory capability test, not a claim of full identity isolation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import secrets
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent

HOSTNAME = '(deny sysctl-read (sysctl-name-prefix "kern.hostname"))'
INTERFACES = '(deny sysctl-read (sysctl-name-prefix "net.route"))(deny system-socket (socket-domain AF_ROUTE))'
DIRECTORY = '(deny mach-lookup (global-name "com.apple.system.opendirectoryd.api" "com.apple.system.opendirectoryd.libinfo" "com.apple.system.opendirectoryd.membership"))'
IOKIT_FIELDS = '(deny iokit-get-properties (iokit-property "IOPlatformUUID" "IOPlatformSerialNumber"))'
LOGIN = '(deny syscall-unix (syscall-number 49))'  # SYS_getlogin in this macOS SDK.
HOST_UUID = '(deny syscall-unix (syscall-number 142))(deny sysctl-read (sysctl-name-prefix "kern.uuid"))'
PREFERENCES_MACH = '(deny mach-lookup (global-name "com.apple.cfprefsd.daemon" "com.apple.cfprefsd.agent"))'
CONFIGD = '(deny mach-lookup (global-name "com.apple.SystemConfiguration.configd"))'
CONFIGD_HELPER = '(deny mach-lookup (global-name "com.apple.SystemConfiguration.helper"))'
SC_PREFERENCES = '(deny user-preference-read (preference-domain "com.apple.SystemConfiguration"))'
POLICIES = {
    "hostname": HOSTNAME,
    "interfaces": INTERFACES,
    "directory_services": DIRECTORY,
    "directory_libinfo": '(deny mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))',
    "directory_api": '(deny mach-lookup (global-name "com.apple.system.opendirectoryd.api"))',
    "directory_membership": '(deny mach-lookup (global-name "com.apple.system.opendirectoryd.membership"))',
    "login_syscall": LOGIN,
    "host_uuid_syscall_and_sysctl": HOST_UUID,
    "iokit_identity_properties": IOKIT_FIELDS,
    "all_iokit_properties": '(deny iokit-get-properties)',
    "all_user_preferences": '(deny user-preference-read)',
    "preferences_daemons_and_reads": PREFERENCES_MACH + '(deny user-preference-read)',
    "system_configuration_configd": CONFIGD,
    "system_configuration_helper": CONFIGD_HELPER,
    "system_configuration_preferences": SC_PREFERENCES,
    "system_configuration_configd_and_preferences": CONFIGD + CONFIGD_HELPER + SC_PREFERENCES + PREFERENCES_MACH,
    "minimal_non_directory_combination": HOSTNAME + INTERFACES + LOGIN + HOST_UUID + IOKIT_FIELDS,
    "combined_identity_sources": HOSTNAME + INTERFACES + DIRECTORY + LOGIN + HOST_UUID + IOKIT_FIELDS,
}
REQUIRED_BLOCKED = [
    "gethostname", "sysctl_hostname", "getlogin", "gethostuuid", "sysctl_kern_uuid", "getifaddrs_names",
    "IOPlatformUUID_single", "IOPlatformUUID_bulk", "IOPlatformSerialNumber_single", "IOPlatformSerialNumber_bulk",
]
IDENTITY_FILE_POLICY_NAMES = (
    "identity_sc_files", "identity_sc_mach_and_files", "identity_locale_global_files",
    "identity_locale_global_and_encoding_files", "identity_locale_mach_and_files",
    "identity_timezone_aliases", "identity_timezone_aliases_and_target", "identity_all_mach_and_files",
    "identity_all_files_and_kernel",
    "identity_all_files_kernel_and_libinfo",
    "identity_sc_min_configd_cfprefs_files", "identity_sc_min_configd_daemon_files", "identity_sc_min_configd_agent_files",
    "identity_locale_min_cfprefs_files", "identity_timezone_canonical_alias",
    "identity_sc_min_domain_files", "identity_locale_min_domain_files",
    "identity_locale_min_agent_files", "identity_locale_min_daemon_files",
    "identity_byhost_listing_only", "identity_all_files_kernel_readwrite", "identity_all_files_kernel_readwrite_byhost",
    "identity_merge_readwrite_candidate", "identity_merge_readwrite_candidate_libinfo",
)


def exact_file_rules(paths, operation="file-read*"):
    if not paths:
        return ""
    return "(deny " + operation + " " + " ".join("(literal " + json.dumps(str(path), ensure_ascii=False) + ")" for path in sorted(paths)) + ")"


def system_identity_files():
    """Discover only specific existing identity files, never whole directories."""
    sources = {}
    categories = {"sc": set(), "locale": set(), "encoding": set(), "tz_alias": set(), "tz_target": set()}
    verification = {"sc_identity_keys": [], "locale_identity_keys": [], "text_encoding_valid": False}

    def include(category, path):
        path = Path(path)
        if not (path.is_file() or path.is_symlink()):
            return
        label = category + "_" + str(sum(name.startswith(category + "_") for name in sources))
        sources[label] = str(path)
        categories[category].add(path)
        if category != "tz_alias":
            try:
                categories[category].add(path.resolve(strict=True))
            except OSError:
                pass

    def plist(path):
        try:
            with path.open("rb") as stream:
                value = plistlib.load(stream)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError, plistlib.InvalidFileException):
            return {}

    for path in (Path("/Library/Preferences/SystemConfiguration/preferences.plist"),):
        value = plist(path)
        system = value.get("System", {})
        computer = system.get("System", {}) if isinstance(system, dict) else {}
        network = system.get("Network", {}) if isinstance(system, dict) else {}
        hostnames = network.get("HostNames", {}) if isinstance(network, dict) else {}
        matched = [key for key, dictionary in (("ComputerName", computer), ("LocalHostName", hostnames)) if isinstance(dictionary, dict) and key in dictionary]
        if matched:
            include("sc", path)
            verification["sc_identity_keys"] = sorted(set(verification["sc_identity_keys"] + matched))

    user_homes = {Path.home()}
    try:
        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        user_homes.add(account_home)
        verification["uid_home_differs_from_environment_home"] = account_home != Path.home()
    except KeyError:
        verification["uid_home_lookup_unavailable"] = True
    roots = (Path("/Library/Preferences"), *(home / "Library/Preferences" for home in sorted(user_homes)))
    for root in roots:
        candidates = [root / ".GlobalPreferences.plist", root / ".GlobalPreferences_m.plist"]
        candidates += list((root / "ByHost").glob(".GlobalPreferences.*.plist"))
        for path in candidates:
            value = plist(path)
            matched = [key for key in value if key in ("AppleLocale", "AppleLanguages", "Country") or key.startswith("AppleICU")]
            if matched:
                include("locale", path)
                verification["locale_identity_keys"] = sorted(set(verification["locale_identity_keys"] + matched))
    for home in user_homes:
        encoding = home / ".CFUserTextEncoding"
        try:
            encoding_valid = bool(re.fullmatch(rb"[0-9a-fA-Fx]+:[0-9a-fA-Fx]+\s*", encoding.read_bytes()))
        except OSError:
            encoding_valid = False
        if encoding_valid:
            include("encoding", encoding)
            verification["text_encoding_valid"] = True

    for path in (Path("/etc/localtime"), Path("/private/etc/localtime"), Path("/var/db/timezone/localtime")):
        if path.is_symlink():
            include("tz_alias", path)
            try:
                target = path.resolve(strict=True)
                if target.is_file():
                    include("tz_target", target)
            except OSError:
                pass
    sc = exact_file_rules(categories["sc"])
    locale = exact_file_rules(categories["locale"])
    encoding_rule = exact_file_rules(categories["encoding"])
    aliases = exact_file_rules(categories["tz_alias"])
    targets = exact_file_rules(categories["tz_target"])
    byhost_directories = set()
    uuid_pattern = re.compile(r"[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}")
    for root in roots:
        candidate = root / "ByHost"
        try:
            if candidate.is_dir() and any(uuid_pattern.search(path.name) for path in candidate.iterdir()):
                byhost_directories.add(candidate.resolve())
        except OSError:
            pass
    byhost_listing_rule = exact_file_rules(byhost_directories, "file-read-data")
    locale_mach = PREFERENCES_MACH + '(deny user-preference-read (preference-domain ".GlobalPreferences"))'
    combined = CONFIGD + CONFIGD_HELPER + locale_mach + SC_PREFERENCES + sc + locale + encoding_rule + aliases
    kernel = HOSTNAME + INTERFACES + LOGIN + HOST_UUID + IOKIT_FIELDS
    write_protection = exact_file_rules(categories["sc"] | categories["locale"] | categories["encoding"] | categories["tz_alias"], "file-write*")
    canonical_alias_paths = {path for path in categories["tz_alias"] if str(path) == "/private/etc/localtime"}
    merge_paths = categories["sc"] | categories["locale"] | categories["encoding"] | canonical_alias_paths
    merge_candidate = CONFIGD + '(deny mach-lookup (global-name "com.apple.cfprefsd.daemon"))' + kernel + exact_file_rules(merge_paths) + exact_file_rules(merge_paths, "file-write*") + byhost_listing_rule
    policies = {
        "identity_sc_files": sc,
        "identity_sc_mach_and_files": CONFIGD + CONFIGD_HELPER + PREFERENCES_MACH + SC_PREFERENCES + sc,
        "identity_locale_global_files": locale,
        "identity_locale_global_and_encoding_files": locale + encoding_rule,
        "identity_locale_mach_and_files": locale_mach + locale + encoding_rule,
        "identity_timezone_aliases": aliases,
        "identity_timezone_aliases_and_target": aliases + targets,
        "identity_all_mach_and_files": combined,
        "identity_all_files_and_kernel": combined + HOSTNAME + INTERFACES + LOGIN + HOST_UUID + IOKIT_FIELDS,
        "identity_all_files_kernel_and_libinfo": combined + HOSTNAME + INTERFACES + LOGIN + HOST_UUID + IOKIT_FIELDS + '(deny mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))',
        "identity_sc_min_configd_cfprefs_files": CONFIGD + PREFERENCES_MACH + sc,
        "identity_sc_min_configd_daemon_files": CONFIGD + '(deny mach-lookup (global-name "com.apple.cfprefsd.daemon"))' + sc,
        "identity_sc_min_configd_agent_files": CONFIGD + '(deny mach-lookup (global-name "com.apple.cfprefsd.agent"))' + sc,
        "identity_locale_min_cfprefs_files": PREFERENCES_MACH + locale + encoding_rule,
        "identity_sc_min_domain_files": CONFIGD + SC_PREFERENCES + sc,
        "identity_locale_min_domain_files": '(deny user-preference-read (preference-domain ".GlobalPreferences"))' + locale + encoding_rule,
        "identity_locale_min_agent_files": '(deny mach-lookup (global-name "com.apple.cfprefsd.agent"))' + locale + encoding_rule,
        "identity_locale_min_daemon_files": '(deny mach-lookup (global-name "com.apple.cfprefsd.daemon"))' + locale + encoding_rule,
        "identity_byhost_listing_only": byhost_listing_rule,
        "identity_all_files_kernel_readwrite": combined + kernel + write_protection,
        "identity_all_files_kernel_readwrite_byhost": combined + kernel + write_protection + byhost_listing_rule,
        "identity_merge_readwrite_candidate": merge_candidate,
        "identity_merge_readwrite_candidate_libinfo": merge_candidate + '(deny mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))',
        "identity_timezone_canonical_alias": exact_file_rules({path for path in categories["tz_alias"] if str(path) == "/private/etc/localtime"}),
    }
    verification["exact_path_counts"] = {category: len(paths) for category, paths in categories.items()}
    verification["resolved_timezone_target_is_profile_zone"] = any(path == Path("/usr/share/zoneinfo/America/Los_Angeles").resolve() for path in categories["tz_target"])
    verification["byhost_identity_directory_count"] = len(byhost_directories)
    directories = {"byhost_" + str(index): str(path) for index, path in enumerate(sorted(byhost_directories))}
    samples = {}
    for label, directory in directories.items():
        candidate = Path(directory)
        try:
            matching = sorted(path for path in candidate.iterdir() if path.is_file() and path.name.startswith(("com.apple.AppleMultitouchTrackpad.", "com.apple.mouse.", "com.apple.screensaver.", "com.apple.windowserver.")) and uuid_pattern.search(path.name))
            if matching:
                samples[label] = str(matching[0])
        except OSError:
            pass
    verification["byhost_known_file_sample_count"] = len(samples)
    return policies, sources, directories, samples, verification


def public_comparison(values, baseline):
    public = {}
    for name, value in values.items():
        record = {key: item for key, item in value.items() if key not in ("digest", "inode") and not key.endswith("_digest")}
        original = baseline.get(name, {})
        if "digest" in value and "digest" in original:
            record["same_as_baseline"] = value["digest"] == original["digest"]
        for component in ("country", "language"):
            digest_key = component + "_digest"
            if digest_key in value and digest_key in original:
                record["same_" + component + "_as_baseline"] = value[digest_key] == original[digest_key]
        if name in ("SCDynamicStore_computer_name", "SCDynamicStore_local_hostname") and "digest" in value:
            record["matches_other_baseline_sources"] = [source for source in ("gethostname", "getlogin", "getpwuid_name", "NSFullUserName") if value["digest"] == baseline.get(source, {}).get("digest")]
        if name == "file_io":
            record["same_inode"] = value.get("inode") == original.get("inode")
            record["same_owner"] = value.get("uid_digest") == original.get("uid_digest")
        public[name] = record
    return public


def assert_native_file(values, name):
    native_file = values["file_io"]
    assert native_file["available"] and native_file["same_inode"] and native_file["same_owner"], name + " changed native fixture file behavior"


PRESERVED_BY_PRODUCTION = ("gethostname", "sysctl_hostname", "getlogin")
PRODUCTION_BLOCKED = tuple(source for source in REQUIRED_BLOCKED if source not in PRESERVED_BY_PRODUCTION)


def assert_minimal_protection(values, baseline, name, required=REQUIRED_BLOCKED):
    assert "policy_error" not in values, values
    for source in required:
        assert not values[source]["available"], name + " left identity source readable: " + source
    for source in ("model_single", "model_bulk"):
        if baseline[source]["available"]:
            assert values[source]["available"] and values[source]["same_as_baseline"], name + " unexpectedly restricted ordinary IOKit model access"
    assert_native_file(values, name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, help="write only the non-sensitive comparison report")
    parser.add_argument("--verbose", action="store_true", help="print full sanitized comparisons")
    parser.add_argument("--guard", type=Path, help="also verify an actual socket-guard executable")
    parser.add_argument("--port", type=int, default=65000, help="guard's allowed local TCP port; no listener is required")
    policy_names = tuple(POLICIES) + IDENTITY_FILE_POLICY_NAMES
    parser.add_argument("--policy", action="append", choices=policy_names, help="run only selected exploratory policies; repeat as needed")
    parser.add_argument("--system-identity-files", action="store_true", help="include precise, verified system-identity file experiments")
    parser.add_argument("--guard-with-policy", action="append", choices=policy_names, help="also run this policy around the actual --guard")
    parser.add_argument("--timezone-mode", choices=("profile", "native"), default="profile", help="use the US TZ value, or remove TZ to inspect native fallback sources")
    parser.add_argument("--clear-cf-encoding", action="store_true", help="remove the inherited CF text-encoding override for a separate control run")
    parser.add_argument("--check-write-protection", action="store_true", help="test destructive write operations only on a temporary replica, never on system sources")
    parser.add_argument("--guard-accounts", action="store_true", help="include the production account-directory restriction")
    parser.add_argument("--guard-identity-files", action="store_true", help="include production system-identity file restrictions")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be from 1 to 65535")
    if args.guard_with_policy and not args.guard:
        parser.error("--guard-with-policy requires --guard")
    available_policies = dict(POLICIES)
    source_paths = {}
    directory_paths = {}
    directory_samples = {}
    source_verification = {}
    selected = (args.policy or []) + (args.guard_with_policy or [])
    if args.system_identity_files or any(name in IDENTITY_FILE_POLICY_NAMES for name in selected):
        identity_policies, source_paths, directory_paths, directory_samples, source_verification = system_identity_files()
        available_policies.update(identity_policies)
    source_contents_before = {}
    for label, path in source_paths.items():
        try:
            source_contents_before[label] = hashlib.sha256(Path(path).read_bytes()).digest()
        except OSError:
            pass
    with tempfile.TemporaryDirectory(prefix="identity-source-probe-", dir="/tmp") as directory:
        directory = Path(directory).resolve()
        binary = directory / "identity-probe"
        fixture = directory / "native-file"
        replica = directory / "identity-replica.plist"
        fixture.write_bytes(b"probe original native file")
        subprocess.run([
            "/usr/bin/clang", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations",
            "-fobjc-arc", "-framework", "Foundation", "-framework", "CoreFoundation", "-framework", "IOKit", "-framework", "SystemConfiguration",
            str(HERE / "identity_probe.m"), "-o", str(binary),
        ], check=True, capture_output=True)
        env = os.environ.copy()
        for key in list(env):
            if key.startswith("DYLD_"):
                env.pop(key)
        env.update({"IDENTITY_PROBE_DIGEST_KEY": secrets.token_hex(32),
            "TZ": "America/Los_Angeles", "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
            "USER": "identity-probe-user", "LOGNAME": "identity-probe-user", "HOSTNAME": "identity-probe-host"})
        env.pop("TZFILE", None)
        env.pop("TZDIR", None)
        if args.clear_cf_encoding:
            env.pop("__CF_USER_TEXT_ENCODING", None)
        if args.timezone_mode == "native":
            env.pop("TZ", None)
        if source_paths:
            env["IDENTITY_PROBE_SOURCE_PATHS"] = json.dumps(source_paths, ensure_ascii=False)
        if directory_paths:
            env["IDENTITY_PROBE_BYHOST_DIRECTORIES"] = json.dumps(directory_paths, ensure_ascii=False)
        if directory_samples:
            env["IDENTITY_PROBE_BYHOST_SAMPLES"] = json.dumps(directory_samples, ensure_ascii=False)
        env.pop("IDENTITY_PROBE_BASELINE_UUID_DIGEST", None)

        def execute(rules=None, prefix=(), protect_replica=False):
            command = [*prefix, str(binary), str(fixture)]
            replica_before = None
            if args.check_write_protection:
                replica.write_bytes(b"replica original identity data")
                replica.chmod(0o600)
                replica_before = (replica.read_bytes(), replica.stat().st_ino, replica.stat().st_uid, replica.stat().st_mode)
                command.append(str(replica))
                if protect_replica:
                    rules = (rules or "") + exact_file_rules({replica}, "file-write*")
            if rules is not None:
                command = ["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)" + rules, *command]
            completed = subprocess.run(command, env=env, capture_output=True, text=True, timeout=15)
            if completed.returncode:
                return None, {"exit": completed.returncode, "policy_error": completed.stderr.replace(str(Path.home()), "$HOST_HOME")[:1500]}
            values = json.loads(completed.stdout)
            if protect_replica:
                replica_after = (replica.read_bytes(), replica.stat().st_ino, replica.stat().st_uid, replica.stat().st_mode) if replica.exists() else None
                denied = all(not values["replica_write_" + operation]["available"] for operation in ("open_truncate", "chmod", "atomic_replace", "unlink"))
                values["replica_identity_file"] = {"available": replica_after == replica_before and denied, "protection_failed": replica_after != replica_before or not denied}
            return values, None

        baseline, failure = execute(None)
        if failure:
            raise RuntimeError(failure)
        if baseline.get("gethostuuid", {}).get("digest"):
            env["IDENTITY_PROBE_BASELINE_UUID_DIGEST"] = baseline["gethostuuid"]["digest"]
        output = {"platform": "macOS", "timezone_mode": args.timezone_mode, "baseline": public_comparison(baseline, baseline), "policies": {}}
        if source_verification:
            output["system_identity_file_verification"] = source_verification
            output["inherited_cf_text_encoding_present"] = "__CF_USER_TEXT_ENCODING" in env
        policies = {name: available_policies[name] for name in args.policy} if args.policy else available_policies
        for name, rules in policies.items():
            values, failure = execute(rules, protect_replica=args.check_write_protection and "_readwrite" in name)
            output["policies"][name] = failure or public_comparison(values, baseline)
            if values is not None:
                assert_native_file(output["policies"][name], name)
        minimum = output["policies"].get("minimal_non_directory_combination")
        if minimum is not None:
            assert_minimal_protection(minimum, output["baseline"], "minimal policy")
        output["baseline_missing_sources"] = [source for source in REQUIRED_BLOCKED if not baseline[source]["available"]]
        if args.guard:
            guard = args.guard.resolve(strict=True)
            flags = ["--ipv4", "--identity-guard", "--hide-interfaces"]
            if args.guard_accounts:
                flags.append("--hide-account-records")
            if args.guard_identity_files:
                flags.append("--identity-files")
            flags.append(str(args.port))
            values, failure = execute(prefix=[str(guard), *flags])
            output["policies"]["production_guard"] = failure or public_comparison(values, baseline)
            assert_minimal_protection(output["policies"]["production_guard"], output["baseline"], "production guard", PRODUCTION_BLOCKED)
            for source in PRESERVED_BY_PRODUCTION:
                if baseline[source]["available"]:
                    result = output["policies"]["production_guard"][source]
                    assert result["available"] and result["same_as_baseline"], source
            output["production_guard"] = {"sha256": hashlib.sha256(guard.read_bytes()).hexdigest(), "arguments": flags}
            for name in args.guard_with_policy or []:
                values, failure = execute(rules=available_policies[name], prefix=[str(guard), *flags])
                label = "production_guard+" + name
                output["policies"][label] = failure or public_comparison(values, baseline)
                if failure:
                    output["layered_guard_policy_supported"] = False
                else:
                    assert_minimal_protection(output["policies"][label], output["baseline"], label, PRODUCTION_BLOCKED)
        assert fixture.read_bytes() == b"probe original native file"
    unchanged = 0
    for label, before in source_contents_before.items():
        try:
            if hashlib.sha256(Path(source_paths[label]).read_bytes()).digest() == before:
                unchanged += 1
        except OSError:
            pass
    if source_contents_before:
        output["system_source_contents_check"] = {"checked": len(source_contents_before), "unchanged": unchanged, "all_unchanged": unchanged == len(source_contents_before)}
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    if args.verbose:
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        for name, values in output["policies"].items():
            if "policy_error" in values:
                print(name + ": policy error: " + values["policy_error"])
                continue
            blocked = [key for key, value in values.items() if not value["available"] and output["baseline"][key]["available"]]
            print(name + ": blocked=" + ",".join(sorted(blocked)) + "; native-file=" + str(values["file_io"]["available"] and values["file_io"]["same_inode"] and values["file_io"]["same_owner"]))
        print("Sanitized output: " + (str(args.out) if args.out else "not saved; use --out"))
    return 1 if any("policy_error" in values or values.get("replica_identity_file", {}).get("protection_failed") for values in output["policies"].values()) else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Report environment marker names/presence only, or emit synthetic fixtures.

No inherited environment value is serialized, hashed or measured. The synthetic
values are public test data, never credentials or copies of a host identifier.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re


SESSION_MARKERS = (
    "TERM_SESSION_ID", "ITERM_SESSION_ID", "SECURITYSESSIONID", "XPC_SERVICE_NAME",
    "LaunchInstanceID", "__CFBundleIdentifier", "CODEX_SESSION_ID", "STARSHIP_SESSION_KEY",
)
PROVENANCE = ("TERM_PROGRAM", "TERM_PROGRAM_VERSION", "LC_TERMINAL", "LC_TERMINAL_VERSION", "ITERM_PROFILE")
REMOTE_METADATA = ("SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "REMOTEHOST")
FUNCTIONAL = (
    "TERM", "COLORTERM", "TERMINFO", "TERMINFO_DIRS", "SSH_AUTH_SOCK", "TMUX", "TMUX_PANE", "STY",
    "DISPLAY", "XAUTHORITY", "PATH", "PWD", "OLDPWD", "SHELL", "SHLVL", "COMMAND_MODE", "XPC_FLAGS",
)


def classification(name):
    if name in SESSION_MARKERS:
        return "session_or_launch_provenance_candidate"
    if name in PROVENANCE:
        return "terminal_product_or_user_profile_label"
    if name in REMOTE_METADATA:
        return "remote_connection_metadata"
    if name in FUNCTIONAL:
        return "functional_environment_review_before_removal"
    return "additional_name_requires_review"


def synthetic_markers():
    return {name: "wrapper-public-session-sentinel-" + str(index)
        for index, name in enumerate(SESSION_MARKERS)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sentinels", action="store_true", help="write synthetic marker JSON instead of auditing")
    args = parser.parse_args()
    if args.sentinels:
        report = synthetic_markers()
    else:
        pattern = re.compile(r"SESSION|INSTANCE|BUNDLE|XPC|TERM_PROGRAM|TERMINAL|SSH_|DISPLAY|XAUTH|VSCODE|TMUX|STY|WINDOW|TTY", re.I)
        names = sorted(set(SESSION_MARKERS + PROVENANCE + REMOTE_METADATA + FUNCTIONAL)
            | {name for name in os.environ if pattern.search(name)})
        report = {"observed_utc": datetime.now(timezone.utc).isoformat(),
            "privacy": "names, presence and classification only; no values, lengths or digests",
            "variables": [{"name": name, "present": name in os.environ,
                "classification": classification(name)} for name in names]}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output_kind": "synthetic_fixture" if args.sentinels else "names_only_audit",
        "variable_count": len(report) if args.sentinels else len(report["variables"])}))


if __name__ == "__main__":
    main()

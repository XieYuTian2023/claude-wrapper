#!/bin/sh
set -eu
root="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
client="${1:?provide the absolute path to the official Claude Code binary}"
work="$(mktemp -d "/tmp/wrapper-bun-contract.XXXXXXXX")"
cleanup() {
  result=$?
  trap - EXIT HUP INT TERM
  if [ "$result" -ne 0 ] && [ -f "$work/log" ]; then
    cat "$work/log" >&2
  fi
  rm -rf "$work"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
mkdir -p "$work/config" "$work/home"
cp "$root/native/bun/test/before.cjs" "$root/native/bun/test/after.cjs" "$work/"
printf '%s\n' '{"userID":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' > "$work/config/.claude.json"
make -C "$root/native/macos" >/dev/null
make -C "$root/native/egress" >/dev/null
installation="$work/installation with spaces : demo"
mkdir "$installation"
cp "$root/native/macos/build/identity-launch" "$root/native/macos/build/identity.cjs" \
  "$root/native/macos/build/libclaude-wrapper.dylib" "$installation/"
(
  cd "$work"
  export HOME="$work/home" CLAUDE_CONFIG_DIR="$work/config"
  export USER="$(/usr/bin/id -un)" HOSTNAME="$(/bin/hostname)"
  export CLAUDE_WRAPPER_DEVICE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  export CLAUDE_WRAPPER_PROXY_URL=http://wrapper:contract-test@127.0.0.1:65000/
  export TZ=America/New_York LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
  export ANTHROPIC_API_KEY=sk-ant-wrapper-contract-dummy
  export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
  export BUN_OPTIONS="--preload $work/before.cjs"
  "$root/native/egress/build/socket-guard" --ipv4 --identity-guard --identity-files 65000 \
    "$installation/identity-launch" --bun "$client" --help > "$work/help" 2> "$work/log"
)
rg -q BUN_IDENTITY_CONTRACT_OK "$work/log"
if env HOME="$work/home" CLAUDE_CONFIG_DIR="$work/config" \
  CLAUDE_WRAPPER_DEVICE_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  TZ=America/New_York LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 BUN_OPTIONS= \
  "$root/native/egress/build/socket-guard" --ipv4 --identity-guard --identity-files 65000 \
  "$installation/identity-launch" --bun "$client" --version > "$work/rejected" 2> "$work/rejected-log"; then
  printf '%s\n' 'Mismatched client identity was accepted' >&2
  exit 1
fi
[ ! -s "$work/rejected" ]
rg -q 'identity initialization failed' "$work/rejected-log"
if env -i PATH=/usr/bin:/bin HOME="$work/home" CLAUDE_CONFIG_DIR="$work/config" \
  CLAUDE_WRAPPER_DEVICE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  ANTHROPIC_BASE_URL=https://gateway.invalid CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=99 \
  TZ=America/New_York LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 \
  "$root/native/egress/build/socket-guard" --ipv4 65000 \
  "$installation/identity-launch" --bun "$client" --version > "$work/oauth" 2> "$work/oauth-log"; then
  printf '%s\n' 'A subscription credential source was accepted for a custom gateway' >&2
  exit 1
fi
[ ! -s "$work/oauth" ]
rg -q 'identity initialization failed' "$work/oauth-log"
printf '%s\n' 'Actual Claude Code Bun identity contract passed'

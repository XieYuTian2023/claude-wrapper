#!/bin/sh
set -eu

build_dir=$1
helper="$build_dir/identity-launch"
fixture="$build_dir/identity-fixture"
real_home=$("$fixture" --home)
tempdir=$(mktemp -d)
cleanup() {
    rm -f "$tempdir/fixture-output" "$tempdir/stdout" "$tempdir/stderr" \
        "$tempdir/hardened-fixture" "$tempdir/identity-launch"
    rmdir "$tempdir"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

export LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8
export CLAUDE_WRAPPER_TEST_SYSNAME="$(/usr/bin/uname -s)"
export CLAUDE_WRAPPER_TEST_RELEASE="$(/usr/bin/uname -r)"
export CLAUDE_WRAPPER_TEST_VERSION="$(/usr/bin/uname -v)"
export CLAUDE_WRAPPER_TEST_MACHINE="$(/usr/bin/uname -m)"
"$helper" --check "$fixture"

run_profile() (
    cd "$tempdir"
    export TZ=$1 HOSTNAME="$(/bin/hostname)" USER="$(/usr/bin/id -un)"
    status=0
    "$helper" "$fixture" "$real_home" "$2" "$3" 'argument with spaces' || status=$?
    test "$status" -eq 42
    test "$(cat fixture-output)" = "host file"
    rm fixture-output
)

run_profile America/New_York -18000 -14400
run_profile America/Phoenix -25200 -25200
test "$("$fixture" --home)" = "$real_home"

status=0
"$helper" /bin/echo "unexpected output" >"$tempdir/stdout" 2>"$tempdir/stderr" || status=$?
test "$status" -eq 126
test ! -s "$tempdir/stdout"
grep -q 'prevents native injection' "$tempdir/stderr"

cp "$fixture" "$tempdir/hardened-fixture"
codesign --force --sign - --options runtime "$tempdir/hardened-fixture" 2>/dev/null
status=0
"$helper" "$tempdir/hardened-fixture" --home >"$tempdir/stdout" 2>"$tempdir/stderr" || status=$?
test "$status" -eq 126
test ! -s "$tempdir/stdout"
grep -q 'prevents native injection' "$tempdir/stderr"

cp "$helper" "$tempdir/identity-launch"
status=0
"$tempdir/identity-launch" "$fixture" --home >"$tempdir/stdout" 2>"$tempdir/stderr" || status=$?
test "$status" -eq 126
test ! -s "$tempdir/stdout"
grep -q 'cannot locate adjacent' "$tempdir/stderr"

printf 'macOS identity fixture passed\n'

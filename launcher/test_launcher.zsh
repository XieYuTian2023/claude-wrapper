#!/bin/zsh -f
# Reversible tests use only a stub wrapper/client and a temporary HOME.
setopt NO_UNSET PIPE_FAIL
unsetopt XTRACE VERBOSE
readonly source_launcher=${0:A:h}/'Launch Claude.command'
workdir=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/claude-launcher.XXXXXXXX") || exit 1
trap '/bin/rm -rf -- "$workdir"' EXIT
trap 'exit 130' HUP INT TERM
package="$workdir/package with spaces"
home_dir="$workdir/temporary home"
profiles_dir="$workdir/profiles with spaces"
capture="$workdir/captured"
path_bin="$workdir/path bin"
project="$workdir/project with spaces"
project_literal="$workdir/"'project $(printf unsafe)'
client="$workdir/"'official client $(printf unsafe)'
/bin/mkdir -p -- "$package" "$home_dir" "$profiles_dir" "$capture" "$path_bin" "$project" "$project_literal"
/bin/cp -- "$source_launcher" "$package/Launch Claude.command"
/bin/chmod +x "$package/Launch Claude.command"
cat > "$package/claude-wrapper" <<'STUB'
#!/bin/zsh -f
setopt NO_UNSET
if (( $# == 4 )) && [[ "$1" == '--profiles-dir' && "$3" == 'profile' && "$4" == 'list' ]]; then
  print -r -- "${STUB_PROFILES-}"
  exit 0
fi
print -rn -- "$#" > "$STUB_CAPTURE/count"
integer index=1
for argument in "$@"; do
  print -rn -- "$argument" > "$STUB_CAPTURE/$index"
  (( index++ ))
done
builtin pwd -P > "$STUB_CAPTURE/cwd"
exit ${STUB_RUN_EXIT:-0}
STUB
cat > "$client" <<'STUB'
#!/bin/zsh -f
print -r -- 'The launcher must not execute the client during preflight.' >&2
exit 99
STUB
/bin/chmod +x "$package/claude-wrapper" "$client"
/bin/cp -- "$client" "$path_bin/claude"

typeset -a base_env case_env
base_env=(
  "PATH=$path_bin:/usr/bin:/bin" "HOME=$home_dir" "STUB_CAPTURE=$capture"
  $'STUB_PROFILES=east\nwest' 'ANTHROPIC_API_KEY=launcher-test-credential-never-print'
  'TEST_PROXY_PASSWORD=launcher-test-credential-never-print'
)
case_env=("CLAUDE_WRAPPER_CLIENT=$client" "CLAUDE_WRAPPER_PROFILES_DIR=$profiles_dir")
integer passed=0
fail_test() { print -ru2 -- "FAIL: $1"; exit 1; }
run_case() {
  local label=$1 expected=$2 input_text=$3
  shift 3
  /bin/rm -f -- "$capture"/*(N)
  print -rn -- "$input_text" > "$workdir/input"
  /usr/bin/env -i "${base_env[@]}" "${case_env[@]}" "$package/Launch Claude.command" "$@" \
    < "$workdir/input" > "$workdir/output" 2>&1
  local result=$?
  [[ "$result" == "$expected" ]] || fail_test "$label: unexpected exit code $result"
  [[ "$(< "$workdir/output")" != *launcher-test-credential-never-print* ]] || fail_test "$label: credential printed"
  (( passed++ ))
}
expect_argv() {
  [[ -f "$capture/count" && "$(< "$capture/count")" == "$#" ]] || fail_test 'argument count'
  integer index=1
  for expected in "$@"; do
    [[ "$(< "$capture/$index")" == "$expected" ]] || fail_test "argument $index"
    (( index++ ))
  done
}
expect_cwd() { [[ "$(< "$capture/cwd")" == "${1:A}" ]] || fail_test 'real working directory'; }
expect_no_launch() { [[ ! -e "$capture/count" ]] || fail_test 'unexpected launch'; }

run_case direct 0 '' east "$project"
expect_argv --profiles-dir "$profiles_dir" run east --target "$client"
expect_cwd "$project"

run_case literal_metacharacters 0 '' west "$project_literal"
expect_argv --profiles-dir "$profiles_dir" run west --target "$client"
expect_cwd "$project_literal"

run_case interactive_number 0 $'2\n'"$project"$'\n'
expect_argv --profiles-dir "$profiles_dir" run west --target "$client"
expect_cwd "$project"

run_case interactive_name 0 $'east\n'"$project_literal"$'\n'
expect_argv --profiles-dir "$profiles_dir" run east --target "$client"
expect_cwd "$project_literal"

case_env=("CLAUDE_WRAPPER_PROFILES_DIR=$profiles_dir")
run_case path_client 0 '' east "$project"
expect_argv --profiles-dir "$profiles_dir" run east --target "${path_bin:A}/claude"

case_env=("CLAUDE_WRAPPER_CLIENT=$client")
run_case default_profiles_directory 0 '' west "$project"
expect_argv --profiles-dir "$home_dir/Library/Application Support/claude-wrapper/profiles" run west --target "$client"
[[ ! -e "$home_dir/Library" ]] || fail_test 'default configuration was created'

case_env=("CLAUDE_WRAPPER_CLIENT=$client" "CLAUDE_WRAPPER_PROFILES_DIR=$profiles_dir" 'STUB_PROFILES=')
run_case no_profiles 1 '' east "$project"
expect_no_launch
[[ "$(< "$workdir/output")" == *"No profiles yet"* ]] || fail_test 'missing profile explanation'

case_env=("CLAUDE_WRAPPER_CLIENT=$workdir/missing-client" "CLAUDE_WRAPPER_PROFILES_DIR=$profiles_dir")
run_case missing_client 1 '' east "$project"
expect_no_launch
[[ "$(< "$workdir/output")" == *"Claude executable is missing or cannot run"* ]] || fail_test 'missing client explanation'

case_env=("CLAUDE_WRAPPER_CLIENT=$client" "CLAUDE_WRAPPER_PROFILES_DIR=$profiles_dir")
run_case missing_project 1 '' east "$workdir/missing-project"
expect_no_launch
run_case unknown_profile 1 '' '$(printf hidden-credential)' "$project"
expect_no_launch
[[ "$(< "$workdir/output")" != *hidden-credential* ]] || fail_test 'input was echoed'
run_case cancelled_input 130 ''
expect_no_launch
run_case empty_direct_profile 1 '' '' "$project"
expect_no_launch
run_case empty_direct_project 1 '' east ''
expect_no_launch
run_case invalid_selection 1 $'99\n'
expect_no_launch

case_env=("CLAUDE_WRAPPER_PROFILES_DIR=$profiles_dir" 'PATH=/usr/bin:/bin')
run_case missing_default_client 1 '' east "$project"
expect_no_launch
[[ "$(< "$workdir/output")" == *Claude\ executable\ not\ found* ]] || fail_test 'default client explanation'

case_env=("CLAUDE_WRAPPER_CLIENT=$client" 'CLAUDE_WRAPPER_PROFILES_DIR=relative-directory')
run_case relative_profile_directory 1 '' east "$project"
expect_no_launch

case_env=('CLAUDE_WRAPPER_CLIENT=relative-client' "CLAUDE_WRAPPER_PROFILES_DIR=$profiles_dir")
run_case relative_client 1 '' east "$project"
expect_no_launch


case_env=("CLAUDE_WRAPPER_CLIENT=$client" "CLAUDE_WRAPPER_PROFILES_DIR=$profiles_dir" 'STUB_RUN_EXIT=42')
run_case target_exit_status 42 '' east "$project"
expect_argv --profiles-dir "$profiles_dir" run east --target "$client"

print -r -- "Launcher stub checks passed: $passed; no real wrapper/client/account requests were run."

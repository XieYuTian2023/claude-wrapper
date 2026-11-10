#!/bin/zsh -f
# Package this file beside claude-wrapper and its native assets.
setopt NO_UNSET PIPE_FAIL
unsetopt XTRACE VERBOSE

readonly bundle_dir=${0:A:h}
readonly wrapper="$bundle_dir/claude-wrapper"
integer interactive_start=0
(( $# < 2 )) && interactive_start=1

finish() {
  local message=$1
  local exit_code=${2:-1}
  print -ru2 -- "$message"
  if (( interactive_start )) && [[ -t 0 ]]; then
    print -nru2 -- 'Press Enter to close this window.'
    IFS= read -r ignored || true
  fi
  exit "$exit_code"
}

usage() {
  print -r -- 'Usage: Launch Claude.command [profile [project directory]]'
  print -r -- 'Optional environment variables: CLAUDE_WRAPPER_CLIENT (absolute path to Claude)'
  print -r -- '                CLAUDE_WRAPPER_PROFILES_DIR (absolute path to profiles)'
}

if [[ ${1:-} == '--help' ]]; then
  usage
  exit 0
fi
if (( $# > 2 )); then
  usage >&2
  exit 2
fi
[[ -f "$wrapper" && -x "$wrapper" ]] || finish 'claude-wrapper is missing from this folder. Use the complete installation package.'

local_profiles_dir=''
if (( ${+CLAUDE_WRAPPER_PROFILES_DIR} )); then
  local_profiles_dir=$CLAUDE_WRAPPER_PROFILES_DIR
else
  [[ ${HOME:-} == /* ]] || finish 'Could not locate the profile directory. Set CLAUDE_WRAPPER_PROFILES_DIR.'
  local_profiles_dir="$HOME/Library/Application Support/claude-wrapper/profiles"
fi
[[ "$local_profiles_dir" == /* ]] || finish 'CLAUDE_WRAPPER_PROFILES_DIR must be an absolute path.'

# profile list exposes names only; never print TOML contents or environment values.
profile_lines=$("$wrapper" --profiles-dir "$local_profiles_dir" profile list 2>/dev/null) ||
  finish 'Could not list profiles. Check the profiles directory and claude-wrapper executable.'
[[ -n "$profile_lines" ]] || finish 'No profiles yet. Create one in Claude Wrapper first.'
typeset -a profiles
profiles=("${(@f)profile_lines}")
for name in "${profiles[@]}"; do
  [[ ${#name} -le 32 && "$name" =~ '^[a-z0-9][a-z0-9_-]*$' ]] ||
    finish 'Invalid profile list. Check the claude-wrapper executable.'
done

client=''
if (( ${+CLAUDE_WRAPPER_CLIENT} )); then
  client=$CLAUDE_WRAPPER_CLIENT
  [[ "$client" == /* ]] || finish 'CLAUDE_WRAPPER_CLIENT must be the absolute path to the official Claude executable.'
else
  client=$(whence -p claude 2>/dev/null) || client=''
  [[ -n "$client" ]] || finish 'Claude executable not found. Install the official client or set CLAUDE_WRAPPER_CLIENT.'
  client=${client:A}
fi
[[ -f "$client" && -x "$client" ]] || finish 'Claude executable is missing or cannot run. Check CLAUDE_WRAPPER_CLIENT.'

selected_profile=${1:-}
if (( $# >= 1 )) && [[ -z "$selected_profile" ]]; then
  finish 'Profile name is required.'
fi
if [[ -z "$selected_profile" ]]; then
  print -r -- 'Available profiles:'
  integer index=1
  for name in "${profiles[@]}"; do
    printf '  %d) %s\n' "$index" "$name"
    (( index++ ))
  done
  print -n -- 'Enter a profile name or number:'
  IFS= read -r selected_profile || finish 'Launch canceled.' 130
  # Prefer an exact name; otherwise accept the displayed index without eval.
  integer found=0
  for name in "${profiles[@]}"; do
    [[ "$selected_profile" == "$name" ]] && found=1
  done
  if (( !found )); then
    index=1
    for name in "${profiles[@]}"; do
      if [[ "$selected_profile" == "$index" ]]; then
        selected_profile=$name
        break
      fi
      (( index++ ))
    done
  fi
fi
integer profile_exists=0
for name in "${profiles[@]}"; do
  [[ "$selected_profile" == "$name" ]] && profile_exists=1
done
(( profile_exists )) || finish 'Profile not found. Enter an existing name or number.'

project_dir=${2:-}
if (( $# >= 2 )) && [[ -z "$project_dir" ]]; then
  finish 'Project directory is required.'
fi
if [[ -z "$project_dir" ]]; then
  print -r -- 'Enter the project path without quotes, or leave it blank to open the folder picker.'
  print -n -- 'Project directory:'
  IFS= read -r project_dir || finish 'Launch canceled.' 130
  if [[ -z "$project_dir" ]]; then
    project_dir=$(/usr/bin/osascript -e 'POSIX path of (choose folder with prompt "Select the Claude project folder")' 2>/dev/null) ||
      finish 'Folder selection canceled.' 130
  fi
fi
[[ -d "$project_dir" ]] || finish 'Project directory is missing or is not a folder. Choose an existing folder.'
builtin cd -- "$project_dir" || finish 'Could not open the project directory. Check its permissions.'

# Arrays/quoted arguments preserve spaces and metacharacters verbatim.
exec "$wrapper" --profiles-dir "$local_profiles_dir" run "$selected_profile" --target "$client"

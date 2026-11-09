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
    print -nru2 -- '按回车关闭窗口。'
    IFS= read -r ignored || true
  fi
  exit "$exit_code"
}

usage() {
  print -r -- '用法：Launch Claude.command [Profile名称 [项目目录]]'
  print -r -- '可选环境变量：CLAUDE_WRAPPER_CLIENT（官方客户端绝对路径）'
  print -r -- '                CLAUDE_WRAPPER_PROFILES_DIR（配置目录绝对路径）'
}

if [[ ${1:-} == '--help' ]]; then
  usage
  exit 0
fi
if (( $# > 2 )); then
  usage >&2
  exit 2
fi
[[ -f "$wrapper" && -x "$wrapper" ]] || finish '缺少同目录的 claude-wrapper 主程序，请使用完整安装包。'

local_profiles_dir=''
if (( ${+CLAUDE_WRAPPER_PROFILES_DIR} )); then
  local_profiles_dir=$CLAUDE_WRAPPER_PROFILES_DIR
else
  [[ ${HOME:-} == /* ]] || finish '无法确定配置目录，请设置 CLAUDE_WRAPPER_PROFILES_DIR。'
  local_profiles_dir="$HOME/Library/Application Support/claude-wrapper/profiles"
fi
[[ "$local_profiles_dir" == /* ]] || finish '配置目录必须是绝对路径，请检查 CLAUDE_WRAPPER_PROFILES_DIR。'

# profile list exposes names only; never print TOML contents or environment values.
profile_lines=$("$wrapper" --profiles-dir "$local_profiles_dir" profile list 2>/dev/null) ||
  finish '无法读取身份配置列表，请检查配置目录与主程序。'
[[ -n "$profile_lines" ]] || finish '尚无身份配置，请先使用主程序创建 Profile 后再启动。'
typeset -a profiles
profiles=("${(@f)profile_lines}")
for name in "${profiles[@]}"; do
  [[ ${#name} -le 32 && "$name" =~ '^[a-z0-9][a-z0-9_-]*$' ]] ||
    finish '配置列表格式异常，请检查主程序。'
done

client=''
if (( ${+CLAUDE_WRAPPER_CLIENT} )); then
  client=$CLAUDE_WRAPPER_CLIENT
  [[ "$client" == /* ]] || finish 'CLAUDE_WRAPPER_CLIENT 必须是官方客户端的绝对路径。'
else
  client=$(whence -p claude 2>/dev/null) || client=''
  [[ -n "$client" ]] || finish '未找到 Claude 客户端。请先安装官方 Claude，或设置 CLAUDE_WRAPPER_CLIENT。'
  client=${client:A}
fi
[[ -f "$client" && -x "$client" ]] || finish '客户端文件不存在或不可执行，请检查 CLAUDE_WRAPPER_CLIENT。'

selected_profile=${1:-}
if (( $# >= 1 )) && [[ -z "$selected_profile" ]]; then
  finish 'Profile 名称不能为空。'
fi
if [[ -z "$selected_profile" ]]; then
  print -r -- '已有身份配置：'
  integer index=1
  for name in "${profiles[@]}"; do
    printf '  %d) %s\n' "$index" "$name"
    (( index++ ))
  done
  print -n -- '输入配置名称或编号：'
  IFS= read -r selected_profile || finish '已取消启动。' 130
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
(( profile_exists )) || finish '未找到所选 Profile，请使用已有配置名称或列表编号。'

project_dir=${2:-}
if (( $# >= 2 )) && [[ -z "$project_dir" ]]; then
  finish '项目目录不能为空。'
fi
if [[ -z "$project_dir" ]]; then
  print -r -- '输入项目目录的真实路径（可含空格，不加引号）；留空打开文件夹选择器。'
  print -n -- '项目目录：'
  IFS= read -r project_dir || finish '已取消启动。' 130
  if [[ -z "$project_dir" ]]; then
    project_dir=$(/usr/bin/osascript -e 'POSIX path of (choose folder with prompt "选择 Claude 项目目录")' 2>/dev/null) ||
      finish '已取消目录选择。' 130
  fi
fi
[[ -d "$project_dir" ]] || finish '项目目录不存在或不是文件夹，请重新选择真实项目目录。'
builtin cd -- "$project_dir" || finish '无法进入项目目录，请检查访问权限。'

# Arrays/quoted arguments preserve spaces and metacharacters verbatim.
exec "$wrapper" --profiles-dir "$local_profiles_dir" run "$selected_profile" --target "$client"

# macOS 双击启动入口

把可执行的 `Launch Claude.command` 复制到完整程序包中，与 `claude-wrapper` 主程序同级；原生 helper、库和 preload 沿用程序包既有布局。脚本只依赖 macOS 自带的 zsh；文件夹选择器使用系统 `osascript`，不需要 Python 或管理员权限。

双击后选择已有 Profile，再输入真实项目目录。路径可以含空格，输入时不加引号；目录处留空会打开系统文件夹选择器。脚本在该真实目录中启动主程序，参数使用独立字符串传递，不使用 `eval`。缺少 Profile 或客户端时会给出明确信息，不自动创建身份或安装软件。

也可从终端直接启动；两个参数齐全时不交互：

```sh
'./Launch Claude.command' west '/absolute/path/project with spaces'
```

`west` 必须是已有配置名称。客户端默认从 PATH 查找 `claude`；可显式指定官方二进制及独立配置目录，路径均须为绝对路径：

```sh
CLAUDE_WRAPPER_CLIENT='/absolute/path/official claude' \
CLAUDE_WRAPPER_PROFILES_DIR='/absolute/path/profiles' \
  './Launch Claude.command' west '/absolute/path/project with spaces'
```

未覆盖配置目录时，使用主程序的默认目录 `~/Library/Application Support/claude-wrapper/profiles`。启动器只读取配置名称，不显示 TOML 内容、代理地址或环境变量值。Finder 双击的环境可能与终端不同；需要上述环境变量时，可按示例从终端启动。客户端兼容性、网络出口验证和身份初始化由主程序负责。

可逆检查使用临时 HOME、替身主程序与替身客户端：

```sh
/bin/zsh -n 'launcher/Launch Claude.command'
/bin/zsh -n launcher/test_launcher.zsh
/bin/zsh launcher/test_launcher.zsh
```

测试涵盖空格和字面元字符路径、交互名称/编号、原始 argv 与真实工作目录、默认与覆盖路径、缺失项、取消输入、错误输入、退出码透传，以及虚拟凭据不出现在输出中。没有运行真实主程序、Claude 客户端、登录或账户请求；系统文件夹选择器未做 GUI 实测。

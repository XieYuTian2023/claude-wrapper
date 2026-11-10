# Claude Wrapper

Claude Wrapper 是面向 macOS 的第三方 Claude Code 启动器。它按配置管理客户端的时区、区域设置和网络连接，在启动前校验公网出口，并可在会话运行期间持续复查。Claude Code 仍从当前工作目录启动，使用宿主系统的文件路径和权限。

| 项目 | 支持范围 |
| --- | --- |
| 系统 | macOS。Intel Mac 已运行验证，Apple Silicon 已完成交叉构建 |
| 网络 | HTTP(S) 代理，或已连接的系统 VPN 隧道 |
| 配置 | 每个 Profile 独立保存启动参数和 Claude Code 配置目录 |
| 分发 | 本地 npm 安装包，包含两种 Mac 架构的预编译文件 |

## 📦 安装

需要已安装的官方 Claude Code 和 npm，以及可用的 HTTP(S) 代理或系统 VPN。下载或构建 `.tgz` 后，在安装包所在目录执行：

```sh
npm install -g ./claude-wrapper-local-0.3.1.tgz
claude-wrapper ui
```

npm 将 `claude-wrapper` 和 `cw` 安装到全局命令目录。更新时安装新版 `.tgz`。卸载命令为 `npm uninstall -g claude-wrapper-local`。Profile 和客户端数据位于 `~/Library/Application Support/claude-wrapper/profiles`。

## ⚙️ 配置与启动

运行 `claude-wrapper ui`，按 `N` 新建 Profile。输入名称后，用上下键移动到「网络方式」，用左右键切换。

| 网络方式 | 配置方法 |
| --- | --- |
| VPN 隧道 | 先连接 VPN。在「VPN 接口」按 `Enter`，选择「自动选择」或列表中的活动接口 |
| HTTP(S) 代理 | 在「代理地址」填写代理服务提供的地址，例如 `http://127.0.0.1:8080` |
| 环境变量代理 | 填写保存代理 URL 的环境变量名，适用于需要认证的代理 |

在「预期出口地区」按 `Enter`，按名称或两位地区代码搜索。按 `Ctrl+S` 保存，再按 `H` 检查公网 IP、地区和 Claude API 的 HTTPS 连通性。API 返回 `401` 或 `405` 表示无凭据探测收到了 HTTP 响应，账号状态由客户端登录流程确认。

在首页按 `Enter` 启动选中的 Profile，或按 `S` 将它设为默认。侧栏用 ★ 标记默认配置。在项目目录中运行 `cw` 可直接启动默认 Profile。只有一份配置时会自动使用它。`cw` 后的参数传给 Claude Code，例如 `cw --version`。

| 快捷键 | 操作 |
| --- | --- |
| `E`、`C`、`D` | 编辑、复制、删除选中的 Profile |
| `P`、`T` | 选择时区预设、指定 Claude Code 程序路径 |
| `H`、`R`、`L` | 检查出口、重置自动固定 IP、查看分类日志 |
| `?`、`Q` | 查看帮助、退出界面 |

复制 Profile 会生成新的设备标识，并在首次启动时使用独立的客户端目录。删除 Profile 会保留原有客户端数据。配置变更在下一次启动时生效。

如需在 zsh 中通过 `claude` 启动 Wrapper，可定义 `claude() { command cw "$@"; }`。直接运行官方客户端时使用 `command claude`。

### 出口策略

| 设置 | 行为 |
| --- | --- |
| 预期出口地区 | 默认 `US`，也可选择其他地区。检测到中国大陆（`CN`）出口时拒绝连接 |
| 固定出口 IP | 可仅校验地区、指定 IPv4 或 IPv6，或通过三次一致的独立探测自动固定 IP |
| 运行中复查 | 托管代理和 VPN 默认每 30 秒复查。支持 5–3600 秒的固定间隔，也支持按流量调整 |

自动复查模式在空闲时约每 30 秒检查，流量密集时最快约每 5 秒检查。采样依据是新建连接数和加密流量字节数。预检失败时客户端无法启动。托管会话运行期间，复查失败会关闭中继并结束客户端进程组。

地区和 IP 只反映探测请求所走的路径。代理或 VPN 按目的地分流时，其他请求的出口可能不同。时区设置和出口地区校验分别配置。服务使用资格以服务提供方的条款为准。

### 命令行

以下命令创建一个使用现有 VPN 的 Profile。第一条命令可用 `--proxy http://127.0.0.1:8080` 替换 `--vpn-interface auto` 来配置 HTTP(S) 代理。

```sh
claude-wrapper profile create work-vpn --vpn-interface auto --exit-check-interval auto
claude-wrapper doctor work-vpn
claude-wrapper run work-vpn -- --version
```

`doctor` 单独执行网络预检。`run` 启动指定 Profile，`--` 后跟客户端参数。使用 `claude-wrapper run work-vpn --dry-run` 查看启动计划，使用 `claude-wrapper profile --help` 查看配置管理命令。

### Profile 文件

Profile 保存为配置目录下的 `<名称>.toml`。下面是 HTTP(S) 代理示例。VPN 配置将 `network` 设为 `"managed-vpn"`，并用 `vpn_interface = "auto"` 替换 `proxy_url`。

```toml
timezone = "America/Los_Angeles"
locale = "en_US.UTF-8"
network = "managed-relay"
proxy_url = "http://127.0.0.1:8080"
expected_exit_country = "US"
expected_exit_ip = "auto"
exit_check_interval_seconds = "auto"
```

省略 `expected_exit_ip` 时仅校验地区。`exit_check_interval_seconds` 也接受整数，例如 `45`。认证代理用 `proxy_env = "TEAM_PROXY"` 指定存放代理 URL 的环境变量。时区支持美国时区，默认区域设置为 `en_US.UTF-8`。单次启动的命令行参数优先于文件中的对应设置。

## 🛠️ 实现与构建

主程序使用 Rust，终端界面使用 Ratatui，macOS 辅助程序使用 C 和 Objective-C。启动链分为三个阶段：

1. **解析配置。** 读取 Profile 和命令行覆盖值，解析客户端路径，通过 `CLAUDE_CONFIG_DIR` 为每个 Profile 选择独立的客户端目录。
2. **建立网络路径。** 托管模式为每个会话创建带随机凭据的本地 HTTP CONNECT 中继。代理模式将连接转发给上游代理。VPN 模式将 TCP 和 DNS 绑定到选定接口。启动前通过中继校验出口，并向 Claude API 发出无凭据 HTTPS HEAD 请求。
3. **启动并监督客户端。** `socket-guard` 用 macOS Seatbelt 限制常规直连和对指定系统身份来源的访问。默认 Bun 模式通过预加载入口加载原生库，并重绑定受支持的时区和区域查询。启动器负责复查出口，并在检查失败时关闭中继、清理会话进程组。

| 代码位置 | 职责 |
| --- | --- |
| [`src/main.rs`](src/main.rs)、[`src/profile.rs`](src/profile.rs)、[`src/client.rs`](src/client.rs) | 命令解析、配置校验、客户端状态 |
| [`src/proxy.rs`](src/proxy.rs)、[`src/relay/`](src/relay/) | 出口探测、代理转发、VPN 绑定和进程管理 |
| [`src/tui.rs`](src/tui.rs)、[`src/journal.rs`](src/journal.rs) | 终端界面和本地事件日志 |
| [`native/egress/`](native/egress/README.md)、[`native/macos/`](native/macos/README.md)、[`native/bun/`](native/bun/README.md) | Seatbelt 规则、原生查询重绑定和 Bun 启动适配 |

源码构建需要 Rust 和 Xcode Command Line Tools。当前使用 Rust 1.97.1。以下命令构建本机架构，并将启动程序和辅助文件放在同一目录：

```sh
cargo build --locked --release
make -C native/macos
make -C native/egress
cp native/macos/build/identity-launch native/macos/build/libclaude-wrapper.dylib \
   native/macos/build/identity.cjs native/egress/build/socket-guard target/release/
./target/release/claude-wrapper ui
```

npm 包由 `scripts/package_npm.py` 从已构建的两种架构生成。脚本校验 Mach-O 架构和归档文件，安装入口按本机架构执行对应的原生程序。[打包脚本](scripts/package_npm.py) · [npm 包说明](npm/README.md)

原生查询覆盖与 Claude Code 的版本和签名策略有关。系统用户名、主机名、项目路径、文件内容和服务账号仍可能反映宿主身份。部分依赖本地监听、系统服务或 Unix 域套接字的工具会受到 Seatbelt 规则限制。[系统规则与已知边界](native/egress/README.md)

## 许可证

本项目的原创代码采用 MIT 许可证。随附的 Fishhook 代码保留其原有许可证。[MIT 许可证](LICENSE) · [Fishhook 许可证](native/macos/LICENSE.fishhook)

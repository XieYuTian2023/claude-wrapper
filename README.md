# Claude Wrapper

Claude Wrapper 是面向 macOS 的第三方 Claude Code 启动器。连接 VPN 后，创建一次 Profile，就可以用 `cw` 启动。Wrapper 会自动选择 VPN 接口、校验公网出口，并按流量调整复查频率。

| 项目 | 支持范围 |
| --- | --- |
| 系统 | macOS。Intel Mac 已运行验证，Apple Silicon 已完成交叉构建 |
| 网络 | HTTP(S) 代理，或已连接的系统 VPN 隧道 |
| 配置 | 多套 Profile 可独立保存设置，并快速切换 |
| 分发 | npm 安装包，包含两种 Mac 架构的预编译文件 |

## 📦 安装

需要已安装的官方 Claude Code 和 npm，以及可用的 HTTP(S) 代理或系统 VPN。优先通过 npm 安装：

```sh
npm install -g claude-wrapper-macos
claude-wrapper ui
```

配置完成后，在项目目录运行 `cw` 即可启动。`claude-wrapper ui` 用于管理配置。

更新可再次运行 `npm install -g claude-wrapper-macos`，卸载用 `npm uninstall -g claude-wrapper-macos`。

如果以前安装过 `claude-wrapper-local`，请先运行 `npm uninstall -g claude-wrapper-local`，再安装 npm 版。新版会沿用 `~/Library/Application Support/claude-wrapper/profiles` 中的配置和客户端数据。

也可以下载安装包，在其所在目录执行 `npm install -g ./claude-wrapper-local-0.3.2.tgz`。[GitHub Release 安装包](https://github.com/XieYuTian2023/claude-wrapper/releases/tag/v0.3.2)

## ⚙️ 配置与启动

连接 VPN 后，运行 `claude-wrapper ui`，按 `N` 新建 Profile，按 `Ctrl+S` 保存。默认会自动选择 VPN 接口、固定出口 IP 和调整复查频率。需要更改网络方式时，用上下键移到对应字段，再用左右键切换。

| 网络方式 | 配置方法 |
| --- | --- |
| VPN 隧道（默认） | 自动选择会优先尝试系统路由使用的隧道，再尝试其他活动隧道。也可在「VPN 接口」指定 |
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

复制 Profile 会创建独立的会话配置。删除 Profile 后，其登录和历史仍可保留。配置变更在下一次启动时生效。

如需在 zsh 中通过 `claude` 启动 Wrapper，可定义 `claude() { command cw "$@"; }`。直接运行官方客户端时使用 `command claude`。

### 出口策略

| 设置 | 行为 |
| --- | --- |
| 预期出口地区 | 默认 `US`，也可选择其他地区。检测到中国大陆（`CN`）出口时拒绝连接 |
| 固定出口 IP | 新建 Profile 默认在三次探测结果一致后固定 IP。也可选择仅校验地区，或指定 IPv4 或 IPv6 |
| 运行中复查 | 托管代理和 VPN 默认自动调整复查间隔，也可设为固定的 5–3600 秒 |

自动复查根据近期流量连续调整间隔。流量越大，间隔越接近 2 秒。流量下降后，间隔逐渐回到约 30 秒。预检失败会阻止启动，运行中的复查失败会结束会话。主动更换节点后，可按 `R` 让配置重新学习出口 IP。对于会轮换 IP 的节点，可选择「仅校验地区」。

地区和 IP 只反映探测请求所走的路径。代理或 VPN 按目的地分流时，其他请求的出口可能不同。时区设置和出口地区校验分别配置。服务使用资格以服务提供方的条款为准。

### 命令行

以下命令创建一个自动选择 VPN 的 Profile。要使用 HTTP(S) 代理，可在创建命令中追加 `--proxy http://127.0.0.1:8080`。

```sh
claude-wrapper profile create work-vpn
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

手写 Profile 时，省略 `expected_exit_ip` 表示仅校验地区。命令行可用 `--region-only` 选择同一行为。`exit_check_interval_seconds` 也接受整数，例如 `45`。认证代理用 `proxy_env = "TEAM_PROXY"` 指定存放代理 URL 的环境变量。时区支持美国时区，默认区域设置为 `en_US.UTF-8`。单次启动的命令行参数优先于文件中的对应设置。

## 🛠️ 实现与构建

主程序使用 Rust，终端界面使用 Ratatui，macOS 辅助程序使用 C 和 Objective-C。主程序解析 Profile、建立会话中继，并在出口和 API 连通性检查通过后启动客户端。各组件的实现细节见下表。

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

兼容性取决于 Claude Code 版本及其所用的系统服务。[系统规则与已知边界](native/egress/README.md)

## 许可证

本项目的原创代码采用 MIT 许可证。随附的 Fishhook 代码保留其原有许可证。[MIT 许可证](LICENSE) · [Fishhook 许可证](native/macos/LICENSE.fishhook)

# Claude Wrapper · macOS

Claude Wrapper 是第三方 Claude Code 启动器，提供按 Profile 配置的时区、区域设置和网络出口校验。安装包包含 Intel 和 Apple Silicon 两种架构。Intel Mac 已运行验证，Apple Silicon 已完成交叉构建。

## 📦 安装与更新

需要官方 Claude Code、npm，以及可用的 HTTP(S) 代理或已连接的系统 VPN。在本地 `.tgz` 所在目录执行：

```sh
npm install -g ./claude-wrapper-local-0.3.1.tgz
claude-wrapper ui
```

更新时安装新版 `.tgz`。卸载命令为 `npm uninstall -g claude-wrapper-local`。Profile 和客户端数据位于 `~/Library/Application Support/claude-wrapper/profiles`。

## ⚙️ 配置与使用

1. 按 `N` 新建 Profile。上下键切换字段，左右键调整「网络方式」。
2. 选择「VPN 隧道」时，在「VPN 接口」按 `Enter` 选择自动或指定活动接口。选择「HTTP(S) 代理」时填写代理地址。认证代理可通过「环境变量代理」读取完整 URL。
3. 在「预期出口地区」按 `Enter` 选择地区，默认 `US`。按 `Ctrl+S` 保存，再按 `H` 检查公网 IP、地区和 API 连通性。
4. 按 `Enter` 启动选中的 Profile，或按 `S` 设为默认。在项目目录中执行 `cw` 直接启动默认配置，附加参数会转交给 Claude Code。

在首页按 `E` 编辑配置，按 `T` 指定 Claude Code 程序路径，按 `L` 查看错误、拦截和出口日志。

### 出口校验

固定出口 IP 支持手动指定，也支持在三次独立探测得到相同 IP 后自动固定。换节点后，按 `R` 重置自动固定值。托管代理和 VPN 支持运行中复查，默认 30 秒，可指定 5–3600 秒。自动模式在空闲时约每 30 秒检查，流量密集时最快约每 5 秒检查。

预检失败会阻止启动。运行中的复查失败会关闭托管会话。探测结果只反映探测请求的出口，代理或 VPN 按目的地分流时，其他请求可能走不同的路径。

### 命令行

```sh
claude-wrapper profile create work-vpn --vpn-interface auto --exit-check-interval auto
claude-wrapper doctor work-vpn
claude-wrapper run work-vpn
```

使用 HTTP(S) 代理时，以 `--proxy` 和代理地址替换 `--vpn-interface auto`。带凭据的代理用 `--proxy-env TEAM_PROXY` 指定保存 URL 的环境变量。运行 `claude-wrapper --help` 查看命令列表。

## 运行机制

npm 负责安装。命令入口按 Mac 架构执行对应的 Rust 程序。本地中继负责网络转发和出口复查，macOS 辅助程序负责常规直连限制和受支持的身份查询。Claude Code 使用当前项目目录和宿主文件权限。原生查询覆盖随客户端版本而变化。包内提供 `runtime-sha256.json` 用于核对运行文件。

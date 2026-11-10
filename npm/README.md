# Claude Wrapper · macOS

Claude Wrapper 是第三方 Claude Code 启动器，提供按 Profile 配置的时区、区域设置和网络出口校验。安装包包含 Intel 和 Apple Silicon 两种架构。Intel Mac 已运行验证，Apple Silicon 已完成交叉构建。

## 📦 安装与更新

需要官方 Claude Code、npm，以及可用的 HTTP(S) 代理或已连接的系统 VPN。通过 npm 安装：

```sh
npm install -g claude-wrapper-macos
claude-wrapper ui
```

更新可再次运行 `npm install -g claude-wrapper-macos`，卸载用 `npm uninstall -g claude-wrapper-macos`。

如果以前安装过 `claude-wrapper-local`，请先运行 `npm uninstall -g claude-wrapper-local`，再安装 npm 版。新版会沿用 `~/Library/Application Support/claude-wrapper/profiles` 中的配置和客户端数据。

## ⚙️ 配置与使用

1. 连接 VPN 后，按 `N` 新建 Profile。新配置默认自动选择 VPN 接口、固定出口 IP 和调整复查频率。
2. 需要改用 HTTP(S) 代理时，用上下键移动到「网络方式」，用左右键切换并填写代理地址。认证代理可通过「环境变量代理」读取完整 URL。
3. 在「预期出口地区」按 `Enter` 选择地区，默认 `US`。按 `Ctrl+S` 保存，再按 `H` 检查公网 IP、地区和 API 连通性。
4. 按 `Enter` 启动选中的 Profile，或按 `S` 设为默认。在项目目录中执行 `cw` 直接启动默认配置，附加参数会转交给 Claude Code。

在首页按 `E` 编辑配置，按 `T` 指定 Claude Code 程序路径，按 `L` 查看错误、拦截和出口日志。

启动提示使用 `[Wrapper/Exit]`、`[Wrapper/Error]` 等标签。`doctor` 或界面中的 `H` 分别报告网络路径、出口地区、固定 IP 和无凭据 HTTPS 探测结果。探测只验证各自的请求，账号状态以客户端登录结果为准。使用 `run <profile> --dry-run` 可离线核对配置来源和 API 端点。

### 出口校验

自动固定 IP 需要三次独立探测得到相同结果。换节点后，按 `R` 重置自动固定值。若节点会轮换 IP，可选择「仅校验地区」。自动复查按近期流量连续调整间隔，流量密集时接近 2 秒，空闲时约 30 秒。也可手动指定 5–3600 秒。

预检失败会阻止启动。运行中的复查失败会关闭托管会话。探测结果只反映探测请求的出口，代理或 VPN 按目的地分流时，其他请求可能走不同的路径。

### 命令行

```sh
claude-wrapper profile create work-vpn
claude-wrapper doctor work-vpn
claude-wrapper run work-vpn
```

使用 HTTP(S) 代理时，可在创建命令中追加 `--proxy` 和代理地址。认证代理使用 `--proxy-env TEAM_PROXY` 指定保存 URL 的环境变量。仅校验地区可用 `--region-only`。运行 `claude-wrapper --help` 查看命令列表。

包内提供 `runtime-sha256.json` 用于核对运行文件。

本项目的原创代码采用 MIT 许可证，详见包内的 `LICENSE`。Fishhook 代码按 `LICENSE.fishhook` 分发。

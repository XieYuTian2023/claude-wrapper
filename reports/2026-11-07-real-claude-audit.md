# 官方 Claude Code 隐私与兼容性审计

日期：2026-11-07。实际运行平台：Intel macOS。项目范围已调整为仅 macOS，Windows 实现和项目的 Windows 构建产物已删除。

## 结论

**在未修改的官方 macOS Claude Code 2.1.169 中，已通过实际出站请求完整复现日期中的四种撇号和中国时区对应的日期分隔符变化。** 这证明该版本存在可观察的分类行为，不能证明服务器如何使用它，更不能据此推断封号原因。

包装后的测试请求使用 Profile 的美国时区与独立设备标识。默认关闭非必要流量后，测试中没有出现此前的 `/api/eval/` 和 `/api/event_logging/` 请求。相同 Profile 重启保持同一设备标识，不同 Profile 使用不同标识。项目设置对受控环境的改写会被拒绝，或由新版客户端直接忽略。

**这些结果不等于完整匿名，也不证明覆盖未来版本的所有读取路径。** 保留真实文件和 HOME、允许原生系统访问、保持官方签名，同时要求所有宿主信息不可识别，存在无法由当前轻量进程包装器消除的冲突。

## 被测试的软件

从官方 npm 平台包取得原始 `claude` Mach-O 二进制，旁路安装在项目的测试目录；未替换用户的全局安装。两版均通过 `codesign --verify --strict`，签名身份为 Anthropic PBC，Team ID 为 `Q6L2SF6YDW`。

| 官方版本 | 架构 | 二进制 SHA-256 |
| --- | --- | --- |
| 2.1.169 | x86_64 | `6d8d510c715b899307b7d29a1062d43e62c99370c55330dac3ec1851a2fbf7c8` |
| 2.1.319 | x86_64 | `af6f1f5510ae98d56a155bf8f007aa9d5b44efccc9c10c8e10ef35039e95a940` |

## 隐藏字符的实际证据

此前的原始报告为 [Claude Code issue #67120](https://github.com/anthropics/claude-code/issues/67120)。报告针对 Windows 2.1.169；以下是本机独立得到的 macOS 请求结果。

测试的所有域名均由本地夹具接收，**没有向这些域名发送外部请求**。

| 2.1.169 的配置条件 | 实际撇号码点 | 日期分隔符 |
| --- | --- | --- |
| `api.audit.test`，上海时区 | U+0027 | `/` |
| `api.audit.cn`，上海时区 | U+2019 | `/` |
| `deepseek.audit.test`，上海时区 | U+02BC | `/` |
| `deepseek.audit.cn`，上海时区 | U+02B9 | `/` |
| `api.audit.test`，洛杉矶时区 | U+0027 | `-` |
| 包装后的 `api.audit.test`，宿主上海、Profile 洛杉矶 | U+0027 | `-` |

在另一次显式保留 `deepseek.audit.cn` 的包装测试中，日期分隔符恢复为 `-`，U+02B9 仍保留。这说明时区统一不会隐藏应用明确知道的 API 域名。为避免继承环境无意选择其他地址，现在只有 Profile 显式配置的 API 地址才会传入客户端；未配置时使用官方默认地址。显式自定义地址仍可能被客户端分类。

2.1.319 先前的 16 次时区／默认与自定义地址对照，以及本轮补充测试中，日期使用 U+0027 与 `-`。这只描述捕获到的路径，不能证明它在其他鉴权、功能开关或配置下不存在分类。

旧版二进制的静态检查也找到了上海／乌鲁木齐时区名称，以及经 Base64 和 XOR 处理的域名、关键词列表。结论以上表的动态请求结果为主，不依赖从静态字符串猜测用途。

## 方法与验证范围

使用真正的官方客户端执行 `claude -p`，并另外在伪终端运行交互式 CLI、接收完整回复、执行 `/exit`。出站 TLS 由本地测试代理接收，测试 CA 只交给测试子进程；生产包装器不解密 TLS、不改写请求正文。代理返回本地构造的 Anthropic JSON／SSE 响应，所以 `OK` 来自夹具，**并非 Anthropic 真实模型响应**。

每次测试使用空项目、临时 HOME 与独立 Claude 配置，仅提供无效测试密钥。请求头中的凭据被脱敏，发现非测试鉴权值即拒绝。捕获包括模型请求、功能评估、遥测、头部及其 JSON／Base64 编码的附加字段。没有使用真实账号或上传用户项目。

包装器的出口预检单独通过本机已连接的代理访问真实 HTTPS GeoIP 服务；该项不是模拟结果。通用 VPN 的绑定接口 TCP、DoH 和 TLS 也单独做了实网测试。请求捕获夹具只允许这一项预检经现有本地代理转发，其他 Claude 请求均在本地结束。

| 范围 | 实际结果 |
| --- | --- |
| 官方版本回归矩阵 | 22/22 符合验证条件，含四种字符、时区对照、两版包装运行和交互 CLI |
| 项目环境改写 | 两版分别尝试 TZ、HOSTNAME、LC_ALL、NO_PROXY、API 地址、配置目录和遥测变量；危险写入在模型请求前拒绝。2.1.319 忽略配置目录设置，设备 ID 保持原值，替代目录未创建 |
| 独立设备标识 | 模型 `metadata.user_id` 使用 A／B 各自的标识；A 重启保持稳定。旧版默认流量还在评估与遥测字段复用该标识 |
| 默认非必要流量关闭 | 包装测试未捕获评估和批量遥测请求；模型及必要配置请求仍存在。官方说明见 [数据使用文档](https://code.claude.com/docs/en/data-usage) |
| 真实文件 API | 真实客户端合约检查确认 `fs`、`fs.promises`、`Bun.file`、`Bun.write` 函数引用原样，写读与 inode 一致；继承的普通文件描述符保留 |
| 身份初始化 | 两个版本均通过真实客户端合约；配置 ID 不匹配时拒绝进入 `--version`；含空格和冒号的安装目录可用 |
| 会话退出 | 正常子进程、普通后代、忽略 TERM 的后代、运行中 CN 探测、活动隧道关闭和定向中断均已验证 |
| 终端 | 50 次快速子进程退出、前台进程组恢复、真实终端输入通过；真实 Claude 交互式 CLI 可完成并退出 |
| 通用 VPN | 本机活动隧道的 DoH／TCP／TLS 实网测试通过；无需调用 Shadowrocket 私有接口 |
| Apple Silicon | Rust 与原生助手交叉构建，尚未实际运行 |

最初的矩阵有一项因“必须报错”的测试预期而失败。核实后发现新版客户端直接忽略配置目录改写，并保持原设备身份。随后使用同一捕获文件重新分析，验证条件改为“拒绝或证实未生效”，没有把实际行为改写成拒绝。

## 仍存在的边界

- **Bun 兼容层**：`process.env` 的常见设置路径受到保护，但 `Bun.env`／`import.meta.env` 的原始环境入口及原生读取不是通用内核拦截。预加载前保留的函数引用、原生扩展和未来新增调用也不保证覆盖。2.1.319 内嵌的 Bun 1.4.4 不允许给单个环境变量安装只读／访问器属性；2.1.169 的 Bun 1.3.14 行为不同。这个运行时差异也说明不能把某一版的 Hook 当作稳定系统边界。检查代码为 `tests/real_claude/runtime_aliases.cjs`，结果在 `reports/evidence/runtime-aliases.json`。[Bun 环境文档](https://bun.sh/docs/runtime/environment-variables)
- **真实文件和系统信息**：HOME、UID、GID、文件内容、Git 配置、钥匙串访问权限、硬件及未覆盖的系统偏好仍属于宿主。即使当前请求没有某字段，也不能证明客户端永远无法读取它。
- **账号**：独立 device ID 不会让同一登录账号变成不同账号。OAuth、真实账号关联、生产远程功能开关与真实模型响应未验证。
- **网络**：每 30 秒 GeoIP 复查不是逐目的地的出口证明，节点可按目标选路；Seatbelt 放行指定端口上的同地址族本机 TCP，不是严格的单一进程或单一数值回环地址规则。其他本机代发进程属于剩余边界。
- **子进程和生命周期**：环境和内核网络限制可继承，Bun 的 JS 身份替换不覆盖所有子进程原生 API。主动逃离进程组、提权、包装器被 SIGKILL 等情况仍需更强的系统机制。
- **交互式附加请求**：夹具捕获到 GitHub TLS 连接因子进程不信任测试 CA 而失败；会话仍完成。该结果不证明更新／安装相关功能完整可用。
- **版本**：没有硬编码只允许某一版本；但初始化确认不能替代新版本的动态隐私审计。当前不能宣称无限制兼容未知未来版本。
- **配置更新**：对新启动立即使用更新的 Profile；活动会话不做身份热切换，需要重启。并发使用同一 Profile 时不应指定相互冲突的设备标识。

因此当前交付是具有真实请求证据的 macOS 原型。若最终验收仍要求所有系统信号和任意未来版本均不可识别，需要调整“完整真实文件可见／不改变客户端／不采用更强系统隔离”中的部分约束；现有证据不足以把该最终目标标为完成。

## 复核

摘要与捕获 SHA-256 保存在 `reports/evidence/2026-11-07-summary.json`。完整本地夹具请求位于 `target/compat/audit/`，仅含测试数据。运行新矩阵需指定一个尚不存在的输出目录和当前可用的本地 HTTP 代理：

```sh
cargo test --locked
make -C native/macos test
make -C native/egress test
native/bun/test/check.sh "$PWD/target/compat/claude-code-2.1.169/package/claude"
native/bun/test/check.sh "$PWD/target/compat/claude-code-2.1.319/package/claude"
python3 tests/real_claude/pty_check.py
python3 tests/real_claude/suite.py --out target/compat/audit/new-suite \
  --wrapper target/release/claude-wrapper --probe-proxy http://127.0.0.1:1082 \
  --old target/compat/claude-code-2.1.169/package/claude \
  --current target/compat/claude-code-2.1.319/package/claude
CLAUDE_WRAPPER_TEST_VPN=auto cargo test --locked \
  relay::vpn::tests::live_vpn_doh_and_tls -- --ignored
```

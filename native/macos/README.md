# macOS 原生身份层

构建需要 macOS 11 或更高版本及 Xcode Command Line Tools。实际 Claude Code 的系统要求还取决于客户端版本。

```sh
make -C native/macos
make -C native/macos test
# 同时构建两个架构切片；不代表两个架构都已实机验证
make -C native/macos ARCHS='x86_64 arm64' BUILD=build/universal
```

## 两种加载方式

| 方式 | 入口与条件 |
| --- | --- |
| `native` | `identity-launch <绝对 Mach-O 路径> [参数...]`，通过 `DYLD_INSERT_LIBRARIES` 提前加载。目标签名必须允许该方式。 |
| `bun` | `identity-launch --bun <绝对 Mach-O 路径> [参数...]`，通过 `BUN_OPTIONS` preload 与 `bun:ffi.dlopen` 同步晚加载原生库，再重绑定身份 API 导入指针。主包装器还必须先配置受保护的网络与身份来源限制。 |

把 `identity-launch`、`libclaude-wrapper.dylib` 与 Bun 模式所需的 `identity.cjs` 放在同一目录。helper 保留参数、工作目录和标准输入输出，返回目标退出码；被信号终止时返回 `128 + 信号编号`。符号链接会解析为真实目标；当前 helper 要求可执行 Mach-O，不直接解释 shell、JS 或 shebang 入口。

`--check` 与 `--check-bun` 只做静态检查，不运行客户端。`--check` 还检查原生注入的签名条件；`--check-bun` 通过不代表 preload、FFI 或原生绑定已成功，运行时仍须完成初始化确认。

实际验证过的 Claude Code 2.1.169 / 2.1.319 保持官方文件和签名不变，能够通过 Bun FFI 加载原生库。这两份客户端不允许 DYLD 环境注入，但允许加载其他签名的库，因此使用 Bun 路径。其他版本或不同签名策略必须重新验证。原生注入对 Hardened Runtime 的授权要求见 Apple 的 [DYLD 环境变量说明](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.security.cs.allow-dyld-environment-variables) 与 [库验证说明](https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.security.cs.disable-library-validation)。本项目不修改签名或系统保护设置。

## 时区与区域接口

| 信号 | 原生接口 |
| --- | --- |
| 时区 | POSIX `TZ`、`CFTimeZoneCopySystem`、`NSTimeZone.systemTimeZone` 及进程默认时区 |
| 区域 | `LC_ALL` / `LANG`、`CFLocaleCopyCurrent`、`CFLocaleCopyPreferredLanguages` 及对应 `NSLocale` 方法 |

主机名、本机用户名及账号记录使用系统原值。原生库重绑定时区、区域与语言接口。

## Bun 初始化与失败关闭

启动时设置 `CLAUDE_WRAPPER_INIT_OWNER=bun`。原生构造函数从 C 环境缓存所有者，Bun 模式绝不写入或关闭 READY 管道；仅在 JS 中删除 READY 环境变量不足以保证这一点，因为 Bun 环境映射与 C `environ` 不保证同步。

生产 preload 的顺序为：

1. 验证 Profile、运行时默认时区/区域和原生库路径，通过 Bun FFI 加载库。
2. 同步调用 `claude_wrapper_activate()`，核对自检和绑定统计。
3. 验证独立客户端状态、受控环境和本地中继代理设置。
4. 调用 `claude_wrapper_clear_bootstrap()`，同步原生 C 环境并清理两份环境中的临时变量。
5. 关闭 preload 描述符，用提前保存并验证过的 READY 描述符写入最终 ACK，再关闭该描述符。

任何初始化检查失败都以 126 退出，不发送成功 ACK。helper 在管道关闭或超时而未收到确认时终止目标。网络和身份来源限制由主包装器在启动客户端前安装，不能依赖 ACK 来阻止初始化前的流量。原生 `native` 入口沿用自身构造函数确认；该确认不能替代 Bun 模式完整的运行时检查。

公开 ABI 见 [rebind.h](rebind.h)：

| 接口 | 合约 |
| --- | --- |
| `int claude_wrapper_activate(void)` | 线程安全、幂等；同步初始化、绑定当前映像并注册后续映像回调，返回 0 或 errno 风格错误。 |
| `uint32_t claude_wrapper_self_test(void)` | 完整配置要求 224，检查时区、区域和语言。它检查库自身功能，不能代替真实应用调用证据。 |
| `int claude_wrapper_get_status(void *, size_t)` | ABI 2、160 字节，全部字段为 `uint64_t`，顺序见头文件；缓冲区过小返回 `EINVAL`。 |
| `int claude_wrapper_clear_bootstrap(void)` | 仅在激活成功后执行，幂等；同步和清理 C 环境，不写入或关闭任何 READY/preload 描述符。 |

Bun preload 要求 ABI/长度匹配、激活错误为 0、自检为 224、`active=1`。主映像包含这些接口时须成功写入匹配的导入槽。解析、写槽、权限准备、权限恢复、恢复后校验及主映像写槽失败计数均须为零，才继续发送 ACK。

`clear_bootstrap` 在 Bun 所有者完成代理 URL 与客户端状态验证后，把私有中继 URL 同步为 C 环境中的六个大小写代理变量，并清空 `NO_PROXY/no_proxy`；同时恢复原来的 `BUN_OPTIONS`，原来没有则删除。随后移除私有 NATIVE_LIBRARY、INIT_OWNER、代理、设备 ID、READY/preload 描述符编号及原 BUN_OPTIONS 等临时环境变量。移除环境变量不等于关闭描述符；最终 ACK 仍由 Bun 使用提前保存的描述符发送。Bun 调用方也清理其独立 JS 环境映射。后续自检和加载回调使用缓存快照，不再依赖这些临时变量。

## 导入重绑定与覆盖边界

[rebind.c](rebind.c) 只修改列出的身份 API 导入指针，跳过库自身，不接管 `dlsym`、普通文件 API 或执行代码。每次写槽先查询原数据页权限，只在需要时临时允许写入，随后恢复并重新核验 current 与 maximum 权限；`VM_PROT_COPY` 可能扩大 maximum 权限，因此两者均须还原。

统计区分遍历、匹配、物理写入和完整成功：`stores_performed` 记录实际写入；`slots_written` 只统计写入且权限恢复、指针校验均成功的槽。`main_slots_*` 单独记录主映像。遍历映像数不能作为覆盖成功数。初始写槽失败返回错误；后续映像的写槽或恢复失败立即以 126 结束进程。库用 NODELETE 常驻，dyld 回调在后续支持映像的 initializer 前绑定其导入。

此前保存的直接函数指针、新的直接 `dlsym` 查找和直接系统调用可以绕开导入重绑定。主包装器以对应系统来源的内核拒绝作为防线，包括已验证的UUID sysctl、host UUID、IOKit 等来源及选择性的系统身份文件规则。这些拒绝返回失败，不会为任意原生调用合成 Profile 值；已缓存信息、未覆盖来源和其他 API 仍需逐项验证，不能由导入绑定成功推导为完整系统身份虚拟化。

普通项目文件保持真实路径和原生文件接口。身份来源文件的选择性限制由内核策略另行实施，不是本库对普通文件读写的代理。真实 home、文件内容、账号数据和应用自身缓存仍可能包含身份信息。库不拦截 socket/DNS，代理环境同步也不能替代主包装器的强制出口控制。

arm64e 认证槽不写入：主映像为 arm64e 时拒绝，其他不支持映像单独计数，属于明确覆盖边界。当前实机运行验证为 Intel macOS；arm64/universal 构建通过不等于 Apple Silicon 已完成实机认证。

## 验证与许可证

```sh
make -C native/macos test
make -C native/macos test-late
make -C native/macos test-late-faults
# 需要现成的两版官方客户端及 socket-guard；不下载、不登录，只跑 --help
make -C native/macos test-late-official
```

原生夹具验证已有与随后加载的 dylib constructor、清理临时环境后的快照、激活前后及重复激活后的数据页 current/max 权限、原始文件函数地址、同一真实 inode、Bun READY 所有权、libinfo 限制下账号查询、可写返回值隔离及非法快照写槽前拒绝。真实客户端检查七个 fs/Bun 文件函数引用不变，并在宿主侧核对内容、inode、官方 SHA256 与严格签名；正常 `--help` 不能单独证明所有身份 API 都被客户端实际调用。

`make test` 还构建不分发的测试库，注入权限准备拒绝、真实恢复后模拟 API 报错、后续映像写槽拒绝，验证无准备成功时零物理写槽、失败时无 READY ACK，以及恢复错误/未来绑定失败的 126 退出和 constructor 不执行。故障入口只存在于 `CW_REBIND_TESTING` 构建，生产导出检查确认不存在。

间接符号遍历基于 [Fishhook](https://github.com/facebook/fishhook/tree/aadc161ac3b80db07a9908851839a17ba63a9eb1)。BSD 版权声明保留在源文件和 [LICENSE.fishhook](LICENSE.fishhook)；分发二进制时须同时分发该许可证。

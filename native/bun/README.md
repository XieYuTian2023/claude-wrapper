# 官方 Claude Code 的 Bun 身份层

`identity = "bun"` 使用 Bun 的 `BUN_OPTIONS --preload` 入口运行 `identity.cjs`，通过 FFI 同步加载原生身份提供层，再验证客户端标识并配置环境保护。目标二进制及签名保持原样。实测的官方 macOS 客户端使用 hardened runtime，拒绝本项目的 DYLD 环境注入，但允许这一晚加载路径。

启动顺序：内核网络/身份来源限制 → 身份助手 → 官方客户端的 Bun 预加载 → 原生激活/实际导入重绑定验证 → JS 与客户端状态校验 → 清理与确认 → 客户端主入口。脚本从继承的只读描述符加载，支持安装路径含空格和冒号。初始化前不提供标准代理变量，初始化后才把本会话中继地址发布到 JS 和原生 C 两份环境；助手等待独立管道确认，失败即结束目标。原生库在 Bun 模式不发送提前确认。

| 范围 | 行为 |
| --- | --- |
| 原生身份 | 激活 [macOS 原生层](../macos/README.md)，实际重绑定当前及随后加载映像的受支持身份导入，校验自检、匹配到的导入槽和数据页权限恢复 |
| 时区与语言 | 使用系统 `TZ`、`LANG`、`LC_ALL`，核对真实 `Intl.DateTimeFormat` 默认解析结果；时钟和日期 API 保持真实 |
| 设备标识 | 启动前核对独立 `CLAUDE_CONFIG_DIR/.claude.json` 中的 `userID`；没有通用请求正文改写 |
| 环境变更 | 拒绝应用或项目设置改变 Profile 控制的身份、配置目录、代理、API 路由与遥测值；变量名称集中在脚本的 `protectedKeys` 中 |
| 文件 | `fs`、`fs.promises`、`Bun.file`、`Bun.write` 原样保留；只在初始化时读取自己的配置文件 |
| 子进程 | 继承环境与内核网络/身份来源限制；未自动注入所有原生 API，查询可能不可用，显式自定义子进程环境仍不由 JS 层完整控制 |

主机名和本机用户名由 Bun 使用系统值。已有 `BUN_OPTIONS` 会先执行并在初始化后恢复，调用者环境必须可信。

原始环境对象支持锁定时，保存的 `process.env` 引用、`Bun.env`、`import.meta.env` 和 ESM 环境别名也锁定受控键，未控制的普通变量仍可修改。官方 2.1.169 内嵌 Bun 1.3.14 已通过此项；2.1.319 内嵌 Bun 1.4.4 不支持该对象描述符，原始别名保持可变，只保留 `process.env` 代理保护并明确输出部分覆盖提示。独立别名测试对此退出 3（UNSUPPORTED），没有计为成功。

HOME 和项目路径使用实际文件系统，用户及所有者信息按系统权限读取。

```sh
make -C native/macos
make -C native/egress
native/bun/test/check.sh /absolute/path/to/official/claude
```

合约夹具在真实官方客户端 `--help` 期间确认应用实际调用了身份 API，并比较原生文件函数引用、读写与 inode。还验证设备标识不匹配时不进入 `--version`。完整请求、不同版本和项目设置的回归测试见 `tests/real_claude/` 和审计报告。

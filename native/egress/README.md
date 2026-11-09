# macOS 本地代理套接字限制

运行 `make -C native/egress` 生成 `native/egress/build/socket-guard`。构建需要 macOS 的 Command Line Tools，使用时无需管理员权限。`make -C native/egress test` 使用 Python 3.9 以上和本地监听器进行测试。

```text
socket-guard [--ipv4 | --ipv6] [--hide-interfaces] [--identity-guard] [--hide-account-records] [--identity-files] PORT /absolute/target [args...]
```

启动器先关闭额外的继承套接字（保留文件、目录、终端和管道）并拒绝套接字形式的标准输入输出，然后用 Seatbelt 应用网络策略。策略只允许目标及其正常启动的子进程连接指定端口上的本机 TCP。`--ipv4` 和 `--ipv6` 将规则限制为代理所用的地址族，省略时两族都可用。Seatbelt 的 `localhost` 匹配器也涵盖相应地址族的本机非回环接口地址，同一端口上的本机监听者都在允许范围内。macOS 15.8.2 的规则编译器只接受 `localhost` 或 `*` 作为地址，拒绝数值回环地址和 CIDR。代理服务和出口校验由外部组件提供。启动参数、环境、工作目录和普通终端或管道形式的标准输入输出传给目标。

`--hide-interfaces` 额外拒绝 `net.route` 系统查询和 `AF_ROUTE` 套接字。验证中，`getifaddrs()` 返回 `EPERM`。独立助手未指定参数时不启用；主启动器的 Bun 模式默认启用，可用 Profile 的 `hide_interfaces = false` 显式覆盖。依赖真实接口枚举的程序可能收到权限错误。

`--identity-guard` 在内核层拒绝`gethostuuid`、`kern.uuid` / `kern.bootsessionuuid`、指定 IOKit 身份属性、两个 NVRAM 身份变量，以及已核对名称的位置/Wi-Fi Mach 服务。属性清单集中在 `socket_guard.c`，包含平台/磁盘/Thunderbolt/显示器/USB 序列号、UUID、MAC、SSID/BSSID/国家代码和 EDID；NVRAM 为 `prev-lang:kbd` 与 `previous-system-uuid`。实际完整 IOService 枚举中，27 种基线存在的身份属性均消失，普通平台 `model` 保留。它不证明所有硬件接口或未来属性都已覆盖。

系统调用编号来自当前目标 SDK 的 `SYS_gethostuuid`，没有在 Rust 或配置文件中硬编码数字。Bun 模式默认启用，可用 `native_identity_guard = false` 显式关闭。

`--hide-account-records` 是独立诊断助手选项，用于测试拒绝 OpenDirectory、libinfo 和 membership 服务。包装器启动 Claude 时使用系统账号查询。

`--identity-files` 使用 [identity_files.h](identity_files.h) 生成选择性内核规则：

- 精确保护系统主机名/接口/Wi-Fi/共享名偏好、自动时区与位置偏好；系统和当前账号 HOME 的 `.GlobalPreferences*`、`.CFUserTextEncoding`；时区与解析器别名。
- 仅拒绝 ByHost 目录本身的数据读取以阻止含机器 UUID 的文件名枚举；已知的非身份子文件仍可直接读取，未禁止整个偏好子树。
- 拒绝 configd、cfprefsd.daemon 及指定身份偏好域的回退，避免只限制一个 API 后仍能通过文件获取真实值。
- 对身份文件同时限制读取和写入；普通项目的路径、内容、元数据与文件接口不接管。系统测试不向真实身份文件写入；写保护用临时副本验证。

顶层 HOME 可为别名。HOME 内的 Library/Preferences/ByHost、系统身份偏好目录或身份叶子若为符号链接，则拒绝启动，而不把其指向的普通项目加入受限列表。路径中的空格、引号、反斜杠和 Unicode 有独立边界测试；控制字符、规则过大等情况拒绝启动。实际本机已有 OS 权限拒绝或不存在的路径不计为新增保护成功。

Bun 模式默认启用文件限制，可通过 `isolate_identity_files` 配置。系统网络偏好文件中的共享名和接口信息仍随整个偏好来源受限。
```sh
python3 native/egress/test_identity_sources.py \
  --guard native/egress/build/socket-guard --port 65000 \
  --guard-accounts --guard-identity-files --system-identity-files \
  --out target/compat/identity-sources/production.json
python3 native/egress/test_registry_identity.py --out target/compat/identity-sources/registry.json
python3 native/egress/test_network_identity_files.py \
  --guard native/egress/build/socket-guard --out target/compat/identity-sources/network-files.json
```

探针先确认基线中来源可读，再检查实际生产助手；普通硬件型号、文件读写、inode 和所有者保留。输出不含实际身份值。初始十条 API 测试之外，账号/偏好回退、目录枚举、完整注册表与真实网络身份文件单独检查，不能将一项通过推断为全量身份隔离。

规则拒绝 UDP、直接连接其他端口或外部主机、网络监听及 Unix 域套接字连接。它还限制 AppleEvents 和已知的 DNS-SD、后台 URLSession 及 LaunchServices 打开 URL 的 Mach 服务。客户端应使用数值回环地址访问现有 HTTP(S) 代理，由代理解析目的域名。测试覆盖本地 TCP 双栈、单栈及 IPv4 映射地址、接口枚举限制、直接 UDP、`mDNSResponder` 套接字、子进程继承限制及真实文件读写。策略保留宿主路径和现有文件权限。[文件 I/O 微基准](../../README.md#验证)

其他 Mach 或系统服务可能提供委托联网能力。现有浏览器、同用户进程、通过文件或管道协作的外部程序以及代理自身的路由都不在该策略的作用域。守护进程启停和同一端口上监听者变动也不会触发重新校验。请把这项能力视为常规子进程的直接套接字限制。

`sandbox_init` 已在 macOS SDK 标记弃用。此实现只在 macOS 15.8.2 Intel 上完成运行验证。应用策略失败时助手退出 125，目标不启动。长期部署可评估 Apple 的 Network Extension 接口，它要求相应的网络扩展能力和签名配置。[Apple Network Extension 配置文档](https://developer.apple.com/documentation/xcode/configuring-network-extensions/)

# Claude 账号封停与连接故障调查

调查日期为 2026-11-09。样本来自 Reddit、GitHub、LINUX DO 和 V2EX 的公开搜索结果。纳入 2026 年发布、有发帖者本人描述的 14 个封停或组织禁用主题。以主题为计数单位，镜像、同帖更新和评论区的其他个案合并或排除。另留两个登录故障作对照。样本是有意选取的公开报告，存在发帖和检索偏差。计数描述这些主题中能看到的证据，无法用于估计总体封号率或各类原因的比例。

## 样本统计

每个主题只进入一类。优先记录通知中明确写出的政策；只有笼统通知时，将有独立信息的自述情境单列。这里的「通知」指帖子展示或转述的通知，平台判定所依据的内部信号不可见。

| 分类 | 主题数 | 能从原帖核对的信息 |
| --- | ---: | --- |
| 通知引用支持地区政策 | 4 | 法国、加拿大两帖展示地区政策通知并更新称申诉后恢复。美国案例称地区通知后收到通用驳回。LINUX DO 案例展示封停与恢复时间线，地区理由来自发帖者转述。 [法国](https://www.reddit.com/r/Anthropic/comments/1u87md9/claude_max_account_suspended_for_supported/) · [加拿大](https://www.reddit.com/r/claude/comments/1xg5es6/claude_suspended_my_account_for_violation_of/) · [美国](https://github.com/anthropics/claude-code/issues/99102) · [LINUX DO](https://linux.do/t/topic/3046697) |
| 通用通知或无具体理由 | 6 | 异常信号、使用政策、申诉失败或使用后被停用。换网、付款、退款、长对话等出现在时间线上，无法从通知得出哪项触发了决定。 [异常信号](https://www.reddit.com/r/ClaudeCode/comments/1wutrb1/account_suspended_due_to_suspicious_signals/) · [开通后被停用](https://www.reddit.com/r/ClaudeCode/comments/1v8q7t3/banned_after_3_minutes_of_a_pro_account_appeal/) · [付款争议](https://www.reddit.com/r/claude/comments/1uhj1tx/anthropic_banned_my_account_after_i_disputed_two/) · [V2EX 1245975](https://v2ex.com/t/1245975) · [V2EX 1223862](https://cn.v2ex.com/t/1223862) · [LINUX DO 3034248](https://linux.do/t/topic/3034248) |
| 共享个人订阅的自述或共享嫌疑 | 2 | 一帖明确自述 3–4 人共用 Max，另一帖更新称组织因共享嫌疑被停用。两帖均无可独立核对的内部归因。 [多人共用](https://www.reddit.com/r/claude/comments/1wz0u1a/my_account_got_suspended/) · [组织共享嫌疑](https://www.reddit.com/r/ClaudeCode/comments/1xa0cs2/account_suspended/) |
| 代办身份验证后停用 | 1 | 发帖者自述第三方代办后停用，贴出的通知仍为通用使用政策理由。 [V2EX 1208691](https://www.v2ex.com/t/1208691) |
| 仅能确认组织禁用提示 | 1 | 客户端显示组织禁用，发帖者推测 VPN。帖子中可核对的是错误和申诉渠道。 [GitHub 67069](https://github.com/anthropics/claude-code/issues/67069) |
| 合计 | **14** |  |

两个对照是「申诉已恢复，认证系统仍显示停用」以及「认证后被错误送回注册流程」。它们说明仅凭登录界面或 CLI 报错不足以区分当前封停和账号状态故障。 [恢复后登录异常](https://github.com/anthropics/claude-code/issues/51588) · [注册流程异常](https://github.com/anthropics/claude-code/issues/83633)

论坛有人转述所谓风控权重表，本样本没有可复核的服务端依据。项目以前实测了 2.1.169 的日期字符行为，证据覆盖客户端请求内容，服务端用途和封停因果仍未知。 [论坛权重推测](https://www.reddit.com/r/ClaudeCode/comments/1xib8ta/how_anthropic_allegedly_determines_to_ban_you/) · [本项目请求审计](2026-11-07-real-claude-audit.md)

## 官方资料可确认的边界

- Anthropic 列出的封停原因包括重复违反使用政策、从不支持的地区创建账号以及违反服务条款。地区资格取决于官方条件，美国 IP 或时区只能描述连接或本地设置。组织被暂停可通过官方限制页面请求复核。 [封停与申诉](https://support.claude.com/en/articles/8241253-safeguards-warnings-and-appeals) · [支持地区列表](https://www.anthropic.com/supported-countries) · [账号地区说明](https://support.claude.com/en/articles/8287232-verify-your-phone-number)
- 个人条款禁止共享账号和凭据。订阅 OAuth 用于本人登录官方客户端，开发者自建集成使用自己的 API 凭据或官方支持的云服务。身份验证由官方流程处理。 [个人条款](https://www.anthropic.com/legal/consumer-terms) · [Claude Code 鉴权规则](https://code.claude.com/docs/en/legal-and-compliance) · [身份验证](https://support.claude.com/en/articles/14328960-identity-verification-on-claude)
- API 401、402、403、429、529 分别可能涉及鉴权、账单、权限、限流和暂时过载。请求的具体错误消息和请求 ID 比单个数字更有诊断价值。本地无鉴权 HEAD 只说明该请求收到什么 HTTP 响应。 [API 错误说明](https://platform.claude.com/docs/en/api/errors)

## 已接入 Wrapper 的措施

| 本地可观测问题 | 措施 |
| --- | --- |
| 代理换了公网出口，探测仍返回美国 | 可在 Profile 的「固定出口 IP」或 CLI 的 `--expected-exit-ip` 配置预期 IP。GeoIP 检查仍验证国家，并额外比较 IP。托管 VPN 与托管代理在启动和每 30 秒的复查都执行比较；不匹配时拒绝启动或关闭中继和会话。应用代理和旧套接字模式只在启动时检查。 |
| API 可达被误读为账号健康 | `doctor` 和 TUI 的 `H` 显示无鉴权 API HTTP 状态。该值和 GeoIP 结果分别展示。成功通过 TLS 并收到 HTTP 响应时，保留原来的连通性判定。 |
| 明确提供的订阅 OAuth 和自定义 API 混用 | Bun 启动发现非官方 API origin 与显式订阅 OAuth 变量（token、token 文件描述符或 refresh token）并存会在网络预检前退出；预加载也检查该组合并保护常见的后续环境设置入口。多个继承的鉴权环境变量同时存在时只提示变量名。CLI 账号和钥匙串里的登录状态由官方客户端管理。 |

固定 IP 比对基于 **GeoIP 请求**，按目的地分流的 VPN 仍可能给 Anthropic 另一出口。定位这类问题需要 VPN 的目标连接出站记录，或由目标服务提供它观察到的来源 IP。服务端封停、账单、身份验证、使用政策判定和申诉属于平台处理范围。

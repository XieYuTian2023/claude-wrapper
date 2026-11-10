//! Shared, credential-free results for doctor, the TUI, and the journal.
use std::{fmt, net::IpAddr};

use serde::{Deserialize, Serialize};

use crate::proxy::{ExitIpError, GeoIpProbeError, UnexpectedExitCountry};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Route {
    Vpn,
    Relay,
    ProxyEnv,
    SocketGuard,
}

impl Route {
    fn label(self) -> &'static str {
        match self {
            Self::Vpn => "VPN-bound relay",
            Self::Relay => "managed CONNECT relay",
            Self::ProxyEnv => "application proxy",
            Self::SocketGuard => "local proxy with socket guard",
        }
    }

    fn scope(self) -> &'static str {
        match self {
            Self::Vpn => "Probe connections use the selected VPN interface.",
            Self::Relay => "Probe connections use the managed relay and its configured upstream.",
            Self::ProxyEnv => {
                "Only the explicit probe connections are verified. Applications can connect directly."
            }
            Self::SocketGuard => {
                "Probe connections use the explicit local proxy. The client socket guard was not run by doctor."
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Exit {
    NotRun,
    Passed(IpAddr),
    RegionMismatch {
        expected: String,
        observed: String,
        ip: IpAddr,
    },
    IpMismatch {
        expected: IpAddr,
        observed: IpAddr,
    },
    Unstable {
        first: IpAddr,
        observed: IpAddr,
    },
    Timeout,
    ConnectionFailed,
    Http(u16),
    InvalidResponse,
    Unavailable,
}

impl Exit {
    pub fn from_error(error: &anyhow::Error) -> Self {
        if let Some(region) = error.downcast_ref::<UnexpectedExitCountry>() {
            return Self::RegionMismatch {
                expected: region.expected.clone(),
                observed: region.observed.clone(),
                ip: region.ip,
            };
        }
        if let Some(reason) = error.downcast_ref::<GeoIpProbeError>() {
            return match reason {
                GeoIpProbeError::Timeout => Self::Timeout,
                GeoIpProbeError::Connection => Self::ConnectionFailed,
                GeoIpProbeError::Http(status) => Self::Http(status.as_u16()),
                GeoIpProbeError::InvalidResponse => Self::InvalidResponse,
            };
        }
        match error.downcast_ref::<ExitIpError>() {
            Some(&ExitIpError::Mismatch { expected, observed }) => {
                Self::IpMismatch { expected, observed }
            }
            Some(&ExitIpError::Unstable { first, observed }) => Self::Unstable { first, observed },
            None => Self::Unavailable,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Pin {
    Unknown,
    RegionOnly,
    Fixed(IpAddr),
    Learning,
    Pinned(IpAddr),
    Learned(IpAddr),
    Failed,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Api {
    NotRun,
    Http(u16),
    Timeout,
    ConnectionFailed,
}

impl Api {
    fn detail(status: u16) -> &'static str {
        match status {
            401 => "authentication required",
            403 => "request refused",
            407 => "proxy authentication required",
            429 => "rate limited",
            500..=599 => "server error",
            _ => "response received",
        }
    }

    fn summary(&self) -> String {
        match *self {
            Self::NotRun => "Not run".into(),
            Self::Timeout => "HTTPS probe timed out".into(),
            Self::ConnectionFailed => "HTTPS connection failed".into(),
            Self::Http(status) => {
                let detail = Self::detail(status);
                format!("HTTP {status} ({detail}; unauthenticated HTTPS probe)")
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Setup {
    Ready,
    InvalidConfiguration,
    CredentialConflict,
    InvalidClient,
    RouteUnavailable,
}

impl Setup {
    fn label(&self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::InvalidConfiguration => "Invalid profile or launch configuration",
            Self::CredentialConflict => {
                "Subscription OAuth conflicts with the configured API endpoint"
            }
            Self::InvalidClient => "Client executable is missing or incompatible",
            Self::RouteUnavailable => "Could not initialize the selected route",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Report {
    pub setup: Setup,
    pub route: Option<Route>,
    pub vpn_interface: Option<String>,
    pub exit: Exit,
    pub region: Option<String>,
    pub pin: Pin,
    pub api: Api,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            setup: Setup::InvalidConfiguration,
            route: None,
            vpn_interface: None,
            exit: Exit::NotRun,
            region: None,
            pin: Pin::Unknown,
            api: Api::NotRun,
        }
    }
}

impl Report {
    pub fn passed(&self) -> bool {
        matches!(self.setup, Setup::Ready)
            && matches!(self.exit, Exit::Passed(_))
            && matches!(self.api, Api::Http(_))
            && !matches!(self.pin, Pin::Failed | Pin::Learning)
    }

    pub fn blocked(&self) -> bool {
        matches!(self.setup, Setup::CredentialConflict)
            || matches!(
                self.exit,
                Exit::RegionMismatch { .. } | Exit::IpMismatch { .. } | Exit::Unstable { .. }
            )
    }

    pub fn summary_zh(&self) -> String {
        match self.setup {
            Setup::InvalidConfiguration => {
                return "配置无效，请检查 Profile、客户端路径和代理设置".into();
            }
            Setup::CredentialConflict => return "订阅 OAuth 与自定义 API 冲突，已阻断".into(),
            Setup::InvalidClient => return "客户端不存在或与所选启动方式不兼容".into(),
            Setup::RouteUnavailable => return "无法初始化所选网络路径，请检查 VPN 或代理".into(),
            Setup::Ready => {}
        }
        let exit = match &self.exit {
            Exit::Passed(ip) => format!("出口 {ip} ({})", self.region.as_deref().unwrap_or("?")),
            Exit::RegionMismatch {
                expected,
                observed,
                ip,
            } => return format!("地区不符：预期 {expected}，实际 {observed} ({ip}) · API 未执行"),
            Exit::IpMismatch { expected, observed } => {
                return format!("IP 不符：预期 {expected}，实际 {observed}");
            }
            Exit::Unstable { first, observed } => {
                return format!("出口 IP 采样不一致：{first} → {observed}");
            }
            Exit::Timeout => return "出口探测超时 · API 未执行".into(),
            Exit::ConnectionFailed => return "出口探测服务连接失败 · API 未执行".into(),
            Exit::Http(status) => return format!("出口探测服务返回 HTTP {status} · API 未执行"),
            Exit::InvalidResponse => return "出口探测响应无效 · API 未执行".into(),
            Exit::Unavailable => return "出口探测失败，按 L 查看日志".into(),
            Exit::NotRun => return "未执行出口探测".into(),
        };
        let api = match self.api {
            Api::NotRun => "未检查 API".into(),
            Api::Timeout => "API 探测超时".into(),
            Api::ConnectionFailed => "API HTTPS 连接失败".into(),
            Api::Http(status) => {
                let detail = match status {
                    401 => "未认证",
                    403 => "请求被拒",
                    407 => "代理需要认证",
                    429 => "限流",
                    500..=599 => "服务端错误",
                    _ => "已收到响应",
                };
                format!("无鉴权 HTTPS 响应 {status}（{detail}）")
            }
        };
        let scope = match self.route {
            Some(Route::ProxyEnv) => "应用代理 · 仅探测路径".into(),
            Some(Route::Vpn) => format!(
                "VPN {}",
                self.vpn_interface.as_deref().unwrap_or("接口未确认")
            ),
            Some(Route::Relay) => "托管代理".into(),
            Some(Route::SocketGuard) => "本地代理 · 未运行客户端守卫".into(),
            None => "网络模式未确认".into(),
        };
        let pin = match self.pin {
            Pin::Learned(_) => " · 已学习 IP",
            Pin::Pinned(_) => " · 自动固定 IP 匹配",
            Pin::Fixed(_) => " · 指定 IP 匹配",
            Pin::RegionOnly => " · 仅校验地区",
            Pin::Learning => " · 尚未固定 IP",
            Pin::Failed => " · 自动固定失败",
            Pin::Unknown => "",
        };
        format!("{exit}{pin}\n{api} · {scope}")
    }

    pub fn journal_summary(&self) -> String {
        let scope = self.route.map_or("route unknown", Route::label);
        let pin = match self.pin {
            Pin::Unknown => "IP policy not evaluated",
            Pin::RegionOnly => "region only",
            Pin::Fixed(_) => "fixed IP",
            Pin::Learning => "auto-pin pending",
            Pin::Pinned(_) => "auto-pinned IP",
            Pin::Learned(_) => "IP learned",
            Pin::Failed => "auto-pin failed",
        };
        format!(
            "{} · {} · {} · {} · {}",
            self.setup.label(),
            self.exit_summary(),
            self.api.summary(),
            scope,
            pin
        )
    }

    fn exit_summary(&self) -> String {
        match &self.exit {
            Exit::Passed(ip) => format!(
                "exit {ip} (region {} matched)",
                self.region.as_deref().unwrap_or("?")
            ),
            Exit::RegionMismatch {
                expected,
                observed,
                ip,
            } => format!("region rejected: expected {expected}, observed {observed} ({ip})"),
            Exit::IpMismatch { expected, observed } => {
                format!("IP rejected: expected {expected}, observed {observed}")
            }
            Exit::Unstable { first, observed } => {
                format!("exit IP changed between samples: {first}, then {observed}")
            }
            Exit::Timeout => "exit probe timed out".into(),
            Exit::ConnectionFailed => "could not connect to the exit probe service".into(),
            Exit::Http(status) => format!("exit probe service returned HTTP {status}"),
            Exit::InvalidResponse => "exit probe service returned an invalid response".into(),
            Exit::Unavailable => "exit probe failed".into(),
            Exit::NotRun => "exit probe not run".into(),
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(out, "setup     {}", self.setup.label())?;
        if let Some(route) = self.route {
            writeln!(out, "route     {}", route.label())?;
            writeln!(out, "scope     {}", route.scope())?;
        }
        if let Some(interface) = &self.vpn_interface {
            writeln!(out, "vpn-used  {interface}")?;
        }
        writeln!(out, "egress    {}", self.exit_summary())?;
        if matches!(self.exit, Exit::IpMismatch { .. } | Exit::Unstable { .. }) {
            if let Some(region) = &self.region {
                writeln!(out, "region    {region} matched before IP rejection")?;
            }
        }
        match self.pin {
            Pin::Unknown => writeln!(out, "ip-policy Not evaluated")?,
            Pin::RegionOnly => writeln!(out, "ip-policy Region only")?,
            Pin::Fixed(ip) | Pin::Pinned(ip) => {
                let outcome = match self.exit {
                    Exit::Passed(_) => "matched",
                    Exit::IpMismatch { .. } => "mismatch",
                    _ => "not verified",
                };
                let mode = if matches!(self.pin, Pin::Pinned(_)) {
                    "Auto-pinned"
                } else {
                    "Fixed"
                };
                writeln!(out, "ip-policy {mode} IP {ip} ({outcome})")?;
            }
            Pin::Learning => writeln!(out, "ip-policy Auto-pin pending")?,
            Pin::Learned(ip) => writeln!(out, "ip-policy Auto-pinned {ip} after matching samples")?,
            Pin::Failed => writeln!(out, "ip-policy Auto-pin failed")?,
        }
        writeln!(out, "api       {}", self.api.summary())?;
        writeln!(
            out,
            "coverage  Account status, DNS bypass, IPv4/IPv6 bypass, and the public exit for other destinations are unverified."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_result_distinguishes_responses_from_unexecuted_checks() {
        let mut report = Report {
            setup: Setup::Ready,
            route: Some(Route::ProxyEnv),
            region: Some("US".into()),
            exit: Exit::Passed("2001:db8::1".parse().unwrap()),
            pin: Pin::RegionOnly,
            ..Report::default()
        };
        for (status, expected) in [
            (401, "authentication required"),
            (403, "request refused"),
            (407, "proxy authentication required"),
            (429, "rate limited"),
            (503, "server error"),
        ] {
            report.api = Api::Http(status);
            let display = report.to_string();
            assert!(report.passed(), "{display}");
            assert!(display.contains(expected), "{display}");
            assert!(display.contains("2001:db8::1"), "{display}");
            assert!(
                display.contains("other destinations are unverified"),
                "{display}"
            );
            assert!(report.journal_summary().contains(expected));
        }
        for api in [Api::Timeout, Api::ConnectionFailed, Api::NotRun] {
            report.api = api;
            assert!(!report.passed());
        }
        assert!(report.to_string().contains("api       Not run"));

        report.exit = Exit::IpMismatch {
            expected: "192.0.2.1".parse().unwrap(),
            observed: "2001:db8::1".parse().unwrap(),
        };
        assert!(report.blocked());
        assert!(report.to_string().contains("matched before IP rejection"));
    }
}

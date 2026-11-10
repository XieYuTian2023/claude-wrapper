mod client;
mod exit_pin;
mod exit_regions;
mod journal;
mod notice;
mod profile;
mod proxy;
#[cfg(target_os = "macos")]
mod relay;
mod tui;

use std::{
    env,
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{self, Command},
};

use anyhow::{Context, Result, ensure};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use profile::{ExitCheckInterval, ExitIp, IdentityMode, NetworkMode, Profile};
use reqwest::Url;

#[derive(Parser)]
#[command(
    version,
    about = "Launch Claude Code with a profile and a verified proxy or VPN exit"
)]
struct Cli {
    #[arg(long, global = true)]
    profiles_dir: Option<PathBuf>,
    #[command(subcommand)]
    action: Option<Action>,
}

#[derive(Subcommand)]
enum Action {
    /// Open the interactive terminal workspace.
    Ui {
        #[arg(long)]
        no_animation: bool,
    },
    /// Launch the default profile directly, or use the only profile if there is one.
    Start {
        #[arg(long, default_value = "claude")]
        target: OsString,
        /// Target arguments, following --.
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// Create, list, copy, or delete per-user TOML profiles.
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    /// Verify the exit, then launch the target with the profile.
    Run {
        #[command(flatten)]
        launch: Launch,
        /// Print the launch plan without probing the network or starting the target.
        #[arg(long)]
        dry_run: bool,
        /// Target arguments, following --.
        #[arg(last = true)]
        args: Vec<OsString>,
    },
    /// Resolve the launch plan and probe the selected exit without starting the target.
    Doctor {
        #[command(flatten)]
        launch: Launch,
    },
}

#[derive(Subcommand)]
enum ProfileAction {
    /// Create a TOML profile from a US template.
    Create {
        name: String,
        #[arg(long, value_enum, default_value = "us-west")]
        template: Template,
        #[command(flatten)]
        overrides: Settings,
    },
    List,
    Copy {
        source: String,
        destination: String,
    },
    Delete {
        name: String,
    },
    /// Forget the automatically pinned exit IP for a profile.
    ResetExitIp {
        name: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Template {
    #[value(name = "us-west")]
    West,
    #[value(name = "us-central")]
    Central,
    #[value(name = "us-east")]
    East,
}

impl Template {
    fn timezone(self) -> &'static str {
        match self {
            Self::West => "America/Los_Angeles",
            Self::Central => "America/Chicago",
            Self::East => "America/New_York",
        }
    }
}

#[derive(Args, Clone, Default)]
struct Settings {
    #[arg(long)]
    timezone: Option<String>,
    #[arg(long)]
    locale: Option<String>,
    /// HTTP(S) proxy URL. Use --proxy-env when the URL contains credentials.
    #[arg(long, conflicts_with = "proxy_env")]
    proxy: Option<String>,
    /// Read the proxy URL from this environment variable.
    #[arg(long)]
    proxy_env: Option<String>,
    /// Bind the macOS managed relay to this active VPN tunnel interface.
    #[arg(long, conflicts_with_all = ["proxy", "proxy_env"])]
    vpn_interface: Option<String>,
    /// Expected public exit IPv4/IPv6 address, or auto to learn it.
    #[arg(long)]
    expected_exit_ip: Option<ExitIp>,
    /// Check the configured region without requiring a fixed public IP.
    #[arg(long, conflicts_with = "expected_exit_ip")]
    region_only: bool,
    /// Expected exit country or region code (defaults to US).
    #[arg(long)]
    expected_exit_country: Option<String>,
    /// Managed exit check cadence, 5–3600 seconds or auto (default).
    #[arg(long)]
    exit_check_interval: Option<ExitCheckInterval>,
    /// macOS guarded relay or VPN, or explicitly allow the proxy environment alone.
    #[arg(long, value_enum)]
    network: Option<NetworkMode>,
    /// Deny macOS network interface enumeration for guarded processes.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    hide_interfaces: Option<bool>,
    /// Restrict hardware identifiers, host UUID, and native location services.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    native_identity_guard: Option<bool>,
    /// Restrict system identity preferences and timezone aliases; ordinary files remain native.
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    isolate_identity_files: Option<bool>,
    /// Use native hooks, Bun runtime identity, or environment variables alone.
    #[arg(long, value_enum)]
    identity: Option<IdentityMode>,
    /// Profile-specific device fingerprint for the audited Bun client transport.
    #[arg(long)]
    device_id: Option<String>,
    /// Allow nonessential Claude telemetry (disabled by default).
    #[arg(long, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    telemetry: Option<bool>,
    /// Explicit Claude API endpoint; defaults to the official endpoint.
    #[arg(long)]
    api_base_url: Option<String>,
}

impl Settings {
    fn apply(self, profile: &mut Profile) {
        if let Some(timezone) = self.timezone {
            profile.timezone = timezone;
        }
        if let Some(locale) = self.locale {
            profile.locale = locale;
        }
        if let Some(proxy) = self.proxy {
            profile.proxy_url = Some(proxy);
            profile.proxy_env = None;
            profile.vpn_interface = None;
            if matches!(profile.network, Some(NetworkMode::ManagedVpn)) {
                profile.network = None;
            }
        }
        if let Some(proxy_env) = self.proxy_env {
            profile.proxy_env = Some(proxy_env);
            profile.proxy_url = None;
            profile.vpn_interface = None;
            if matches!(profile.network, Some(NetworkMode::ManagedVpn)) {
                profile.network = None;
            }
        }
        if let Some(interface) = self.vpn_interface {
            profile.vpn_interface = Some(interface);
            profile.proxy_url = None;
            profile.proxy_env = None;
            profile.network = Some(NetworkMode::ManagedVpn);
        }
        if let Some(ip) = self.expected_exit_ip {
            profile.expected_exit_ip = Some(ip);
        } else if self.region_only {
            profile.expected_exit_ip = None;
        }
        if let Some(country) = self.expected_exit_country {
            profile.expected_exit_country = Some(country.to_ascii_uppercase());
        }
        if let Some(interval) = self.exit_check_interval {
            profile.exit_check_interval_seconds = Some(interval);
        }
        if let Some(network) = self.network {
            profile.network = Some(network);
        }
        if let Some(hide_interfaces) = self.hide_interfaces {
            profile.hide_interfaces = Some(hide_interfaces);
        }
        if let Some(native_identity_guard) = self.native_identity_guard {
            profile.native_identity_guard = Some(native_identity_guard);
        }
        if let Some(isolate_identity_files) = self.isolate_identity_files {
            profile.isolate_identity_files = Some(isolate_identity_files);
        }
        if let Some(identity) = self.identity {
            profile.identity = Some(identity);
        }
        if let Some(device_id) = self.device_id {
            profile.device_id = Some(device_id.to_ascii_lowercase());
        }
        if let Some(telemetry) = self.telemetry {
            profile.telemetry = Some(telemetry);
        }
        if let Some(api_base_url) = self.api_base_url {
            profile.api_base_url = Some(api_base_url);
        }
    }
}

#[derive(Args, Clone)]
struct Launch {
    profile: String,
    #[arg(long, default_value = "claude")]
    target: OsString,
    /// Directory containing identity-launch and its sibling library.
    #[arg(long)]
    native_dir: Option<PathBuf>,
    /// Location of the macOS socket-guard helper.
    #[arg(long)]
    socket_guard: Option<PathBuf>,
    #[command(flatten)]
    overrides: Settings,
}

struct Plan {
    profile: Profile,
    proxy: Option<Url>,
    target: PathBuf,
    identity_helper: Option<PathBuf>,
    network: Network,
    credential_variables: Vec<String>,
    bun_identity: bool,
    client_config: PathBuf,
    auto_exit_pin: Option<PathBuf>,
}

enum Network {
    ProxyEnv,
    SocketGuard(PathBuf),
    ManagedRelay(PathBuf),
    ManagedVpn(PathBuf),
}

impl Plan {
    fn exit_policy(&self) -> proxy::ExitPolicy<'_> {
        proxy::ExitPolicy {
            geoip_url: self.profile.geoip_url.as_deref(),
            country: self.profile.exit_country(),
            expected_ip: match self.profile.expected_exit_ip {
                Some(ExitIp::Fixed(ip)) => Some(ip),
                _ => None,
            },
            auto_pin: self.auto_exit_pin.as_deref(),
        }
    }

    fn check_credentials(&self) -> Result<()> {
        if !self.bun_identity {
            return Ok(());
        }
        const SUBSCRIPTION_OAUTH: [&str; 3] = [
            "CLAUDE_CODE_OAUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
            "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
        ];
        let active = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"]
            .into_iter()
            .chain(SUBSCRIPTION_OAUTH)
            .filter(|name| {
                env::var_os(name).is_some_and(|value| !value.is_empty())
                    && !self
                        .credential_variables
                        .iter()
                        .any(|removed| removed == name)
            })
            .collect::<Vec<_>>();
        if let Some(target) = &self.profile.api_base_url {
            let custom = proxy::parse_geoip(target)?.origin()
                != Url::parse("https://api.anthropic.com")?.origin();
            ensure!(
                !custom || !active.iter().any(|name| SUBSCRIPTION_OAUTH.contains(name)),
                "explicit Claude subscription OAuth credential is incompatible with a custom API endpoint"
            );
        }
        if active.len() > 1 {
            notice::emit(
                notice::Level::Warning,
                format_args!(
                    "检测到多项 Claude 鉴权设置（{}），请确认客户端使用的凭据",
                    active.join(", ")
                ),
            );
        }
        Ok(())
    }

    fn api_probe_url(&self) -> Result<Option<Url>> {
        self.bun_identity
            .then(|| {
                proxy::parse_geoip(
                    self.profile
                        .api_base_url
                        .as_deref()
                        .unwrap_or("https://api.anthropic.com/v1/models"),
                )
            })
            .transpose()
    }

    fn prepare(dir: &Path, launch: Launch) -> Result<Self> {
        let mut profile = profile::load(dir, &launch.profile)?;
        let mut credential_variables = profile.proxy_env.iter().cloned().collect::<Vec<_>>();
        launch.overrides.apply(&mut profile);
        if let Some(variable) = &profile.proxy_env
            && !credential_variables.contains(variable)
        {
            credential_variables.push(variable.clone());
        }
        profile.validate()?;
        let proxy = if profile.vpn_interface.is_some() {
            None
        } else {
            Some(proxy::endpoint(&profile)?)
        };
        let network = match profile.network {
            Some(network) => network,
            None if profile.vpn_interface.is_some() => NetworkMode::ManagedVpn,
            None => NetworkMode::ManagedRelay,
        };

        let exe = env::current_exe().context("could not resolve the wrapper executable path")?;
        let sibling = exe
            .parent()
            .context("could not resolve the wrapper executable directory")?;
        let network = match network {
            NetworkMode::ProxyEnv => {
                ensure!(proxy.is_some(), "proxy-env requires an HTTP(S) proxy");
                ensure!(
                    launch.socket_guard.is_none(),
                    "--socket-guard requires managed-relay or socket-guard"
                );
                ensure!(
                    !profile.hide_interfaces.unwrap_or(false),
                    "--hide-interfaces requires managed-relay or socket-guard on macOS"
                );
                ensure!(
                    !profile.native_identity_guard.unwrap_or(false),
                    "--native-identity-guard requires a guarded network mode"
                );
                ensure!(
                    !profile.isolate_identity_files.unwrap_or(false),
                    "--isolate-identity-files requires a guarded network mode"
                );
                Network::ProxyEnv
            }
            NetworkMode::ManagedRelay | NetworkMode::ManagedVpn | NetworkMode::SocketGuard => {
                let guard = launch
                    .socket_guard
                    .unwrap_or_else(|| sibling.join("socket-guard"));
                let guard = require_file(guard, "socket guard helper")?;
                if matches!(network, NetworkMode::ManagedVpn) {
                    ensure!(
                        profile.vpn_interface.is_some(),
                        "managed-vpn requires --vpn-interface or vpn_interface in the profile"
                    );
                    Network::ManagedVpn(guard)
                } else if matches!(network, NetworkMode::ManagedRelay) {
                    ensure!(proxy.is_some(), "managed-relay requires an HTTP(S) proxy");
                    Network::ManagedRelay(guard)
                } else {
                    let proxy = proxy
                        .as_ref()
                        .context("socket-guard requires an HTTP(S) proxy")?;
                    ensure!(
                        matches!(proxy.host_str(), Some("127.0.0.1" | "[::1]")),
                        "socket-guard requires a loopback proxy on 127.0.0.1 or [::1]"
                    );
                    Network::SocketGuard(guard)
                }
            }
        };

        let target = which::which(&launch.target).with_context(|| {
            format!(
                "could not locate target {:?}; set --target to the executable",
                launch.target
            )
        })?;
        let identity = profile.identity.unwrap_or(IdentityMode::Bun);
        let bun_identity = matches!(identity, IdentityMode::Bun);
        ensure!(
            !bun_identity || matches!(network, Network::ManagedRelay(_) | Network::ManagedVpn(_)),
            "Bun identity mode requires managed-relay or managed-vpn"
        );
        let identity_helper = match identity {
            IdentityMode::Env => {
                ensure!(
                    launch.native_dir.is_none(),
                    "--native-dir requires --identity native"
                );
                None
            }
            IdentityMode::Native | IdentityMode::Bun => {
                let helper = "identity-launch";
                let library = if bun_identity {
                    "identity.cjs"
                } else {
                    "libclaude-wrapper.dylib"
                };
                let dir = launch.native_dir.as_deref().unwrap_or(sibling);
                require_file(dir.join(library), "native identity library")?;
                if bun_identity {
                    require_file(
                        dir.join("libclaude-wrapper.dylib"),
                        "native identity provider",
                    )?;
                }
                Some(require_file(dir.join(helper), "native identity launcher")?)
            }
        };
        let auto_exit_pin = if matches!(profile.expected_exit_ip, Some(ExitIp::Auto)) {
            Some(profile::exit_pin_path(dir, &launch.profile)?)
        } else {
            None
        };
        Ok(Self {
            profile,
            proxy,
            target,
            identity_helper,
            network,
            credential_variables,
            bun_identity,
            client_config: std::path::absolute(dir.join("clients").join(&launch.profile))?,
            auto_exit_pin,
        })
    }

    fn report(&self) {
        println!("target    {}", self.target.display());
        println!("timezone  {}", self.profile.timezone);
        println!("locale    {}", self.profile.locale);
        println!("config    {}", self.client_config.display());
        println!("exit-region  {}", self.profile.exit_country());
        if matches!(
            self.network,
            Network::ManagedRelay(_) | Network::ManagedVpn(_)
        ) {
            match self.profile.exit_check_interval() {
                ExitCheckInterval::Seconds(seconds) => println!("exit-interval  {seconds}s"),
                ExitCheckInterval::Mode(_) => println!(
                    "exit-interval  auto ({}–{}s)",
                    profile::AUTO_MIN_SECONDS,
                    profile::AUTO_IDLE_SECONDS
                ),
            }
        }
        if let Some(ip) = self.profile.expected_exit_ip {
            println!("expected-exit  {}", String::from(ip));
        }
        println!(
            "api       {}",
            self.profile
                .api_base_url
                .as_deref()
                .unwrap_or("https://api.anthropic.com (official default)")
        );
        if let Some(proxy) = &self.proxy {
            println!("proxy     {}", proxy.origin().ascii_serialization());
        } else if let Some(interface) = &self.profile.vpn_interface {
            println!("vpn       {interface}");
        }
        match &self.identity_helper {
            Some(helper) if self.bun_identity => {
                println!("identity  Bun runtime ({})", helper.display())
            }
            Some(helper) => println!("identity  native ({})", helper.display()),
            None => println!("identity  environment variables"),
        }
        match &self.network {
            Network::ManagedRelay(guard) => println!(
                "network   per-launch CONNECT relay with configured exit checks ({})",
                guard.display()
            ),
            Network::ManagedVpn(guard) => println!(
                "network   VPN-bound CONNECT relay with configured exit checks ({})",
                guard.display()
            ),
            Network::SocketGuard(guard) => println!(
                "network   host-local TCP port {} ({})",
                self.proxy
                    .as_ref()
                    .unwrap()
                    .port_or_known_default()
                    .unwrap(),
                guard.display()
            ),
            Network::ProxyEnv => {
                println!("network   application proxy settings only; direct sockets allowed")
            }
        }
        if self.profile.hide_interfaces.unwrap_or(self.bun_identity) {
            println!("interfaces  enumeration denied");
        }
        if self
            .profile
            .native_identity_guard
            .unwrap_or(self.bun_identity)
        {
            println!("identity-api  native UUID/hardware/location sources restricted");
        }
        if self
            .profile
            .isolate_identity_files
            .unwrap_or(self.bun_identity)
        {
            println!("identity-files  system identity preferences restricted");
        }
    }

    fn check_native_target(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        if let Some(helper) = &self.identity_helper {
            let status = Command::new(helper)
                .env_remove("DYLD_INSERT_LIBRARIES")
                .arg(if self.bun_identity {
                    "--check-bun"
                } else {
                    "--check"
                })
                .arg(&self.target)
                .status()
                .context("could not check macOS native identity compatibility")?;
            ensure!(
                status.success(),
                "macOS native identity check failed; use --identity env for an environment-only launch"
            );
        }
        Ok(())
    }

    fn prepare_client_config(&mut self) -> Result<()> {
        self.profile.device_id = Some(client::prepare(
            &self.client_config,
            self.profile.device_id.as_deref(),
        )?);
        Ok(())
    }

    fn command(&self, args: Vec<OsString>, effective_proxy: &Url) -> Result<Command> {
        let mut chain = Vec::new();
        if let Network::SocketGuard(guard)
        | Network::ManagedRelay(guard)
        | Network::ManagedVpn(guard) = &self.network
        {
            chain.push(guard.as_os_str().to_owned());
            chain.push(
                if effective_proxy.host_str() == Some("[::1]") {
                    "--ipv6"
                } else {
                    "--ipv4"
                }
                .into(),
            );
            if self.profile.hide_interfaces.unwrap_or(self.bun_identity) {
                chain.push("--hide-interfaces".into());
            }
            if self
                .profile
                .native_identity_guard
                .unwrap_or(self.bun_identity)
            {
                chain.push("--identity-guard".into());
            }
            if self
                .profile
                .isolate_identity_files
                .unwrap_or(self.bun_identity)
            {
                chain.push("--identity-files".into());
            }
            chain.push(
                effective_proxy
                    .port_or_known_default()
                    .context("guard proxy port missing")?
                    .to_string()
                    .into(),
            );
        }
        if let Some(helper) = &self.identity_helper {
            chain.push(helper.as_os_str().to_owned());
            if self.bun_identity {
                chain.push("--bun".into());
            }
        }
        chain.push(self.target.as_os_str().to_owned());
        let mut chain = chain.into_iter();
        let mut command = Command::new(chain.next().context("empty launch command")?);
        command.args(chain).args(args);

        for (key, _) in env::vars_os() {
            let upper = key.to_string_lossy().to_ascii_uppercase();
            if matches!(
                upper.as_str(),
                "HTTP_PROXY"
                    | "HTTPS_PROXY"
                    | "ALL_PROXY"
                    | "NO_PROXY"
                    | "DYLD_INSERT_LIBRARIES"
                    | "TZDIR"
                    | "TZFILE"
                    | "CFFIXED_USER_HOME"
                    | "__CF_USER_TEXT_ENCODING"
                    | "SSH_CLIENT"
                    | "SSH_CONNECTION"
                    | "REMOTE_ADDR"
                    | "REMOTE_HOST"
                    | "REMOTE_USER"
                    | "APPLELOCALE"
                    | "APPLELANGUAGES"
            ) || upper.starts_with("LC_")
                || upper.starts_with("CLAUDE_WRAPPER_")
            {
                command.env_remove(key);
            }
        }
        if matches!(
            self.network,
            Network::ManagedRelay(_) | Network::ManagedVpn(_)
        ) {
            for variable in &self.credential_variables {
                command.env_remove(variable);
            }
            if self.identity_helper.is_some() {
                command.env("CLAUDE_WRAPPER_GROUP_SUPERVISED", "1");
            }
        }
        if self.bun_identity
            && env::var_os("CLAUDE_WRAPPER_DIAGNOSTICS").is_some_and(|value| value == "1")
        {
            command.env("CLAUDE_WRAPPER_DIAGNOSTICS", "1");
        }
        let url = effective_proxy.as_str();
        command
            .env("HTTP_PROXY", url)
            .env("HTTPS_PROXY", url)
            .env("ALL_PROXY", url)
            .env("NO_PROXY", "")
            .env("TZ", &self.profile.timezone)
            .env("LANG", &self.profile.locale)
            .env("LC_ALL", &self.profile.locale)
            .env("LANGUAGE", self.profile.locale.split('.').next().unwrap());
        command.env("CLAUDE_CONFIG_DIR", &self.client_config);
        if let Some(api_base_url) = &self.profile.api_base_url {
            command.env("ANTHROPIC_BASE_URL", api_base_url);
        } else {
            command.env_remove("ANTHROPIC_BASE_URL");
        }
        // This launcher selects the Anthropic API. Cloud-provider routing must not
        // silently override a Profile's endpoint using inherited shell settings.
        for name in [
            "CLAUDE_CODE_USE_BEDROCK",
            "CLAUDE_CODE_USE_VERTEX",
            "CLAUDE_CODE_USE_FOUNDRY",
        ] {
            command.env_remove(name);
        }
        if !self.profile.telemetry.unwrap_or(false) {
            command
                .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
                .env("DISABLE_TELEMETRY", "1")
                .env("DISABLE_ERROR_REPORTING", "1")
                .env("CLAUDE_CODE_ENABLE_TELEMETRY", "0")
                .env("DO_NOT_TRACK", "1");
        }
        #[cfg(unix)]
        command
            .env("http_proxy", url)
            .env("https_proxy", url)
            .env("all_proxy", url)
            .env("no_proxy", "");
        if self.bun_identity {
            for name in [
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "NO_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
                "no_proxy",
            ] {
                command.env_remove(name);
            }
            command
                .env("CLAUDE_WRAPPER_PROXY_URL", url)
                .env(
                    "CLAUDE_WRAPPER_DEVICE_ID",
                    self.profile.device_id.as_ref().unwrap(),
                )
                .env("CLAUDE_CODE_GZIP_REQUEST_BODIES", "0");
        }
        Ok(command)
    }
}

fn require_file(path: PathBuf, role: &str) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    ensure!(path.is_file(), "{role} missing at {}", path.display());
    Ok(path)
}

fn manage(dir: &Path, action: ProfileAction) -> Result<()> {
    match action {
        ProfileAction::Create {
            name,
            template,
            overrides,
        } => {
            let mut profile = Profile::new(template.timezone())?;
            if overrides
                .network
                .is_some_and(|network| !matches!(network, NetworkMode::ManagedVpn))
            {
                profile.vpn_interface = None;
            }
            overrides.apply(&mut profile);
            println!("{}", profile::save(dir, &name, &profile)?.display());
        }
        ProfileAction::List => {
            for name in profile::list(dir)? {
                println!("{name}");
            }
        }
        ProfileAction::Copy {
            source,
            destination,
        } => {
            let mut profile = profile::load(dir, &source)?;
            profile.device_id = Some(profile::new_device_id()?);
            println!("{}", profile::save(dir, &destination, &profile)?.display());
        }
        ProfileAction::Delete { name } => profile::delete(dir, &name)?,
        ProfileAction::ResetExitIp { name } => {
            profile::reset_exit_pin(dir, &name)?;
            println!("已清除 {name} 的自动出口 IP");
        }
    }
    Ok(())
}

fn saved_launch(profile: String, target: OsString) -> Launch {
    Launch {
        profile,
        target,
        native_dir: None,
        socket_guard: None,
        overrides: Settings::default(),
    }
}

fn dispatch(cli: Cli) -> Result<i32> {
    if matches!(&cli.action, None | Some(Action::Ui { .. }))
        && (!io::stdin().is_terminal() || !io::stdout().is_terminal())
    {
        println!("交互界面需要真实终端。也可使用 profile、doctor、run 命令。\n");
        Cli::command().print_help()?;
        println!();
        return Ok(0);
    }
    let dir = profile::directory(cli.profiles_dir)?;
    let action = match cli.action {
        None | Some(Action::Ui { .. }) => {
            let no_animation = matches!(cli.action, Some(Action::Ui { no_animation: true }));
            match tui::run(dir.clone(), no_animation)? {
                tui::Outcome::Exit(code) => return Ok(code),
                tui::Outcome::Launch { profile, target } => Action::Run {
                    launch: saved_launch(profile, target),
                    dry_run: false,
                    args: Vec::new(),
                },
            }
        }
        Some(Action::Start { target, args }) => Action::Run {
            launch: saved_launch(
                profile::startup_name(&dir)
                    .inspect_err(|error| journal::failure(&dir, None, "start", error))?,
                target,
            ),
            dry_run: false,
            args,
        },
        Some(action) => action,
    };
    let (operation, profile_name) = match &action {
        Action::Run { launch, .. } => ("run", Some(launch.profile.clone())),
        Action::Doctor { launch } => ("doctor", Some(launch.profile.clone())),
        _ => ("profile", None),
    };
    let result = (|| -> Result<i32> {
        match action {
            Action::Ui { .. } | Action::Start { .. } => unreachable!(),
            Action::Profile { action } => manage(&dir, action)?,
            Action::Doctor { launch } => {
                let plan = Plan::prepare(&dir, launch)?;
                plan.check_credentials()?;
                plan.report();
                plan.check_native_target()?;
                let exit = plan.exit_policy();
                let api = plan.api_probe_url()?;
                #[cfg(target_os = "macos")]
                if matches!(plan.network, Network::ManagedVpn(_)) {
                    let checked = relay::doctor_vpn(
                        plan.profile
                            .vpn_interface
                            .as_deref()
                            .context("VPN interface missing")?,
                        exit,
                        api.as_ref(),
                    )?;
                    print_preflight(checked, exit.country);
                    return Ok(0);
                }
                let proxy = plan
                    .proxy
                    .as_ref()
                    .context("this network mode requires an HTTP(S) proxy")?;
                #[cfg(target_os = "macos")]
                if matches!(plan.network, Network::ManagedRelay(_)) {
                    print_preflight(relay::doctor(proxy, exit, api.as_ref())?, exit.country);
                    return Ok(0);
                }
                let ip = proxy::check(proxy, exit)?;
                println!("exit      {ip} ({})", exit.country);
            }
            Action::Run {
                launch,
                dry_run,
                args,
            } => {
                let mut plan = Plan::prepare(&dir, launch)?;
                plan.check_credentials()?;
                plan.check_native_target()?;
                if dry_run {
                    plan.report();
                    return Ok(0);
                }
                plan.prepare_client_config()?;
                let exit = plan.exit_policy();
                let api = plan.api_probe_url()?;
                let interval = plan.profile.exit_check_interval();
                #[cfg(target_os = "macos")]
                if matches!(plan.network, Network::ManagedVpn(_)) {
                    return relay::run_vpn(
                        plan.profile
                            .vpn_interface
                            .as_deref()
                            .context("VPN interface missing")?,
                        exit,
                        api.as_ref(),
                        interval,
                        |local| plan.command(args, local),
                    );
                }
                let proxy = plan
                    .proxy
                    .as_ref()
                    .context("this network mode requires an HTTP(S) proxy")?;
                #[cfg(target_os = "macos")]
                if matches!(plan.network, Network::ManagedRelay(_)) {
                    return relay::run(proxy, exit, api.as_ref(), interval, |local_proxy| {
                        plan.command(args, local_proxy)
                    });
                }
                let ip = proxy::check(proxy, exit)?;
                notice::emit(
                    notice::Level::Exit,
                    format_args!("出口检查通过 · {ip} ({})", exit.country),
                );
                if matches!(plan.network, Network::ProxyEnv) {
                    notice::emit(
                        notice::Level::Warning,
                        format_args!("环境变量代理模式允许忽略代理的程序直连"),
                    );
                }
                let command = plan.command(args, proxy)?;
                io::stdout().flush()?;
                #[cfg(unix)]
                {
                    use std::os::unix::process::CommandExt;
                    let mut command = command;
                    return Err(command.exec()).context("could not start launch command");
                }
            }
        }
        Ok(0)
    })();
    match &result {
        Err(error) => journal::failure(&dir, profile_name.as_deref(), operation, error),
        Ok(code) if operation == "run" && (1..=127).contains(code) => {
            journal::record(
                &dir,
                profile_name.as_deref(),
                operation,
                journal::Event::ClientExit(*code),
            );
        }
        _ => {}
    }
    result
}

#[cfg(target_os = "macos")]
fn print_preflight(checked: relay::Preflight, country: &str) {
    println!("exit      {} ({country})", checked.exit_ip);
    if let Some(interface) = checked.vpn_interface {
        println!("vpn-used  {interface}");
    }
    if let Some(status) = checked.api_status {
        println!(
            "api-http  {} (unauthenticated HTTPS probe)",
            status.as_u16()
        );
    }
}

fn main() {
    match dispatch(Cli::parse()) {
        Ok(code) => process::exit(code),
        Err(error) => {
            let level =
                if error.is::<proxy::UnexpectedExitCountry>() || error.is::<proxy::ExitIpError>() {
                    notice::Level::Blocked
                } else {
                    notice::Level::Error
                };
            notice::emit(level, format_args!("{error:#}"));
            process::exit(1);
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn managed_override_removes_the_stored_proxy_credential_variable() {
        let dir = tempfile::tempdir().unwrap();
        let profile = Profile {
            timezone: "America/Chicago".into(),
            locale: "en_US.UTF-8".into(),
            proxy_url: None,
            proxy_env: Some("STORED_UPSTREAM_SECRET".into()),
            geoip_url: None,
            expected_exit_ip: None,
            expected_exit_country: None,
            exit_check_interval_seconds: None,
            network: None,
            identity: Some(IdentityMode::Env),
            hide_interfaces: None,
            native_identity_guard: None,
            isolate_identity_files: None,
            vpn_interface: None,
            device_id: None,
            telemetry: None,
            api_base_url: None,
        };
        profile::save(dir.path(), "test", &profile).unwrap();
        let executable = env::current_exe().unwrap();
        for (source_option, source_value) in [
            ("--proxy", "http://127.0.0.1:8080"),
            ("--vpn-interface", "auto"),
        ] {
            let cli = Cli::try_parse_from([
                OsString::from("claude-wrapper"),
                "run".into(),
                "test".into(),
                "--target".into(),
                executable.as_os_str().to_owned(),
                "--socket-guard".into(),
                executable.as_os_str().to_owned(),
                source_option.into(),
                source_value.into(),
            ])
            .unwrap();
            let Some(Action::Run { launch, .. }) = cli.action else {
                unreachable!();
            };
            let plan = Plan::prepare(dir.path(), launch).unwrap();
            let local = Url::parse("http://session:local-token@127.0.0.1:12345").unwrap();
            let command = plan.command(Vec::new(), &local).unwrap();
            let vars = command
                .get_envs()
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(
                vars.get(std::ffi::OsStr::new("STORED_UPSTREAM_SECRET")),
                Some(&None)
            );
            assert_eq!(
                vars.get(std::ffi::OsStr::new("HTTPS_PROXY")),
                Some(&Some(std::ffi::OsStr::new(local.as_str())))
            );
            let args = command.get_args().collect::<Vec<_>>();
            assert_eq!(args[0], "--ipv4");
            assert_eq!(args[1], "12345");
        }
    }
}
#[cfg(not(target_os = "macos"))]
compile_error!("claude-wrapper supports macOS only");

use std::{
    env, fs,
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

pub const DEFAULT_EXIT_CHECK_INTERVAL: u64 = 30;
pub const MIN_EXIT_CHECK_INTERVAL: u64 = 5;
pub const MAX_EXIT_CHECK_INTERVAL: u64 = 3600;

pub fn valid_exit_check_interval(seconds: u64) -> bool {
    (MIN_EXIT_CHECK_INTERVAL..=MAX_EXIT_CHECK_INTERVAL).contains(&seconds)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ExitCheckInterval {
    Seconds(u64),
    Mode(ExitCheckMode),
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitCheckMode {
    Auto,
}

impl ExitCheckInterval {
    pub fn is_auto(self) -> bool {
        matches!(self, Self::Mode(ExitCheckMode::Auto))
    }

    pub fn idle_seconds(self) -> u64 {
        match self {
            Self::Seconds(seconds) => seconds,
            Self::Mode(_) => DEFAULT_EXIT_CHECK_INTERVAL,
        }
    }
}

impl FromStr for ExitCheckInterval {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if value.eq_ignore_ascii_case("auto") {
            Ok(Self::Mode(ExitCheckMode::Auto))
        } else {
            Ok(Self::Seconds(
                value.parse().context("use a number of seconds or auto")?,
            ))
        }
    }
}

impl std::fmt::Display for ExitCheckInterval {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Seconds(seconds) => write!(output, "{seconds}"),
            Self::Mode(_) => output.write_str("auto"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    ManagedRelay,
    ManagedVpn,
    SocketGuard,
    ProxyEnv,
}

#[derive(Clone, Copy, Deserialize, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityMode {
    Native,
    Bun,
    Env,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum ExitIp {
    Auto,
    Fixed(IpAddr),
}

impl FromStr for ExitIp {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if value.eq_ignore_ascii_case("auto") {
            return Ok(Self::Auto);
        }
        Ok(Self::Fixed(
            value
                .parse()
                .context("use an IPv4 or IPv6 address, or auto")?,
        ))
    }
}

impl TryFrom<String> for ExitIp {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        value.parse()
    }
}

impl From<ExitIp> for String {
    fn from(value: ExitIp) -> Self {
        match value {
            ExitIp::Auto => "auto".into(),
            ExitIp::Fixed(ip) => ip.to_string(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub timezone: String,
    pub locale: String,
    pub proxy_url: Option<String>,
    pub proxy_env: Option<String>,
    pub geoip_url: Option<String>,
    pub expected_exit_ip: Option<ExitIp>,
    pub expected_exit_country: Option<String>,
    pub exit_check_interval_seconds: Option<ExitCheckInterval>,
    pub network: Option<NetworkMode>,
    pub identity: Option<IdentityMode>,
    pub hide_interfaces: Option<bool>,
    pub native_identity_guard: Option<bool>,
    pub isolate_identity_files: Option<bool>,
    pub vpn_interface: Option<String>,
    pub device_id: Option<String>,
    pub telemetry: Option<bool>,
    pub api_base_url: Option<String>,
}

impl Profile {
    pub fn exit_country(&self) -> &str {
        self.expected_exit_country.as_deref().unwrap_or("US")
    }

    pub fn exit_check_interval(&self) -> ExitCheckInterval {
        self.exit_check_interval_seconds
            .unwrap_or(ExitCheckInterval::Seconds(DEFAULT_EXIT_CHECK_INTERVAL))
    }

    pub fn validate(&self) -> Result<()> {
        validate_us_timezone(&self.timezone)?;
        let country = self.exit_country();
        ensure!(country != "CN", "mainland China exits (CN) are blocked");
        ensure!(
            crate::exit_regions::name(country).is_some()
                || (self.geoip_url.is_some()
                    && country.len() == 2
                    && country.bytes().all(|byte| byte.is_ascii_uppercase())),
            "expected_exit_country must be a recognized two-letter region code, such as US, JP, or CA"
        );
        ensure!(
            valid_exit_check_interval(self.exit_check_interval().idle_seconds()),
            "exit_check_interval_seconds must be between {MIN_EXIT_CHECK_INTERVAL} and {MAX_EXIT_CHECK_INTERVAL}"
        );
        if let Some(device_id) = &self.device_id {
            ensure!(
                device_id.len() == 64
                    && device_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "device_id must contain 64 lowercase hexadecimal characters"
            );
        }
        ensure!(
            self.locale
                .strip_suffix("_US.UTF-8")
                .is_some_and(|language| {
                    (2..=3).contains(&language.len())
                        && language.bytes().all(|b| b.is_ascii_lowercase())
                }),
            "locale must be a US UTF-8 locale such as en_US.UTF-8"
        );
        ensure!(
            self.proxy_url.is_none() || self.proxy_env.is_none(),
            "configure one of proxy_url or proxy_env"
        );
        if let Some(interface) = &self.vpn_interface {
            ensure!(
                !interface.is_empty()
                    && interface.len() < 16
                    && interface
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)),
                "VPN interface must be a system interface name such as utun6"
            );
            ensure!(
                self.proxy_url.is_none() && self.proxy_env.is_none(),
                "configure either a VPN interface or an HTTP(S) proxy"
            );
        }
        if let Some(network) = self.network {
            ensure!(
                matches!(network, NetworkMode::ManagedVpn) == self.vpn_interface.is_some(),
                "managed-vpn requires vpn_interface; other network modes require an HTTP(S) proxy source"
            );
        }
        if let Some(url) = &self.proxy_url {
            crate::proxy::parse_proxy(url, false)?;
        }
        if let Some(name) = &self.proxy_env {
            ensure!(
                name.as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_uppercase() || *b == b'_')
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "proxy_env must be an uppercase environment variable name"
            );
        }
        if let Some(url) = &self.geoip_url {
            crate::proxy::parse_geoip(url)?;
        }
        if let Some(url) = &self.api_base_url {
            let parsed = crate::proxy::parse_geoip(url)
                .context("api_base_url must be a credential-free HTTPS URL")?;
            ensure!(
                parsed.query().is_none(),
                "api_base_url must not contain a query string"
            );
        }
        Ok(())
    }
}

pub fn new_device_id() -> Result<String> {
    use std::fmt::Write;
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("could not generate a profile device ID"))?;
    let mut id = String::with_capacity(64);
    for byte in bytes {
        write!(id, "{byte:02x}")?;
    }
    Ok(id)
}

pub fn directory(override_dir: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(dir);
    }
    let path =
        env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Application Support"));
    Ok(path
        .filter(|dir| dir.is_absolute())
        .context("could not determine the per-user profile directory; set --profiles-dir")?
        .join("claude-wrapper")
        .join("profiles"))
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
}

fn file(dir: &Path, name: &str) -> Result<PathBuf> {
    ensure!(
        valid_name(name),
        "profile name must contain 1–32 lowercase ASCII letters, digits, hyphens, or underscores, and start with a letter or digit"
    );
    Ok(dir.join(format!("{name}.toml")))
}

pub fn load(dir: &Path, name: &str) -> Result<Profile> {
    let path = file(dir, name)?;
    let input =
        fs::read_to_string(&path).with_context(|| format!("could not read {}", path.display()))?;
    let mut fields: toml::Table = toml::from_str(&input).map_err(|error| {
        anyhow::anyhow!(
            "invalid profile TOML in {} near byte {}",
            path.display(),
            error.span().map_or(0, |span| span.start)
        )
    })?;
    // Profiles from earlier versions may still contain retired account aliases.
    for name in ["hostname", "username", "hide_account_records"] {
        fields.remove(name);
    }
    fields
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid profile fields in {}", path.display()))
}

pub fn save(dir: &Path, name: &str, profile: &Profile) -> Result<PathBuf> {
    let path = file(dir, name)?;
    profile.validate()?;
    // Deleting a Profile intentionally retains Claude's login/history. Never
    // attach a new identity to that retained client state by reusing its name.
    match fs::symlink_metadata(dir.join("clients").join(name)) {
        Ok(_) => {
            bail!("retained Claude state already exists for profile {name}; use a new profile name")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("could not inspect retained Claude state"),
    }
    fs::create_dir_all(dir).with_context(|| format!("could not create {}", dir.display()))?;
    let mut temp = NamedTempFile::new_in(dir)?;
    temp.write_all(toml::to_string_pretty(profile)?.as_bytes())?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(&path)
        .map_err(|error| error.error)
        .with_context(|| format!("could not create {}", path.display()))?;
    Ok(path)
}

/// Atomically edit an existing Profile without changing its device identity or client state.
pub fn update(dir: &Path, name: &str, replacement: &Profile) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let path = file(dir, name)?;
    let metadata = fs::symlink_metadata(&path).context("could not inspect profile for editing")?;
    ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() },
        "profile editing requires an owned regular file without shared links"
    );
    let original = load(dir, name)?;
    let mut updated = replacement.clone();
    updated.device_id = original.device_id;
    updated.validate()?;
    let mut temp = NamedTempFile::new_in(dir)?;
    temp.write_all(toml::to_string_pretty(&updated)?.as_bytes())?;
    temp.as_file().sync_all()?;
    let current = fs::symlink_metadata(&path)?;
    ensure!(
        current.dev() == metadata.dev()
            && current.ino() == metadata.ino()
            && current.nlink() == 1
            && !current.file_type().is_symlink(),
        "profile changed while editing; reload before saving"
    );
    temp.persist(&path)
        .map_err(|error| error.error)
        .context("could not atomically update profile")?;
    Ok(path)
}

pub fn list(dir: &Path) -> Result<Vec<String>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("could not list {}", dir.display()));
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(name) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_suffix(".toml"))
            && valid_name(name)
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

const DEFAULT_PROFILE_FILE: &str = ".default-profile";

pub fn default_name(dir: &Path, names: &[String]) -> Result<Option<String>> {
    let name = match fs::read_to_string(dir.join(DEFAULT_PROFILE_FILE)) {
        Ok(name) => name,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(match names {
                [name] => Some(name.clone()),
                _ => None,
            });
        }
        Err(error) => return Err(error).context("无法读取默认配置"),
    };
    let name = name.trim();
    ensure!(
        valid_name(name),
        "默认配置无效，请打开 claude-wrapper ui 并按 S 重新设置"
    );
    ensure!(
        names.iter().any(|candidate| candidate == name),
        "默认配置 {name} 已不存在，请打开 claude-wrapper ui 并按 S 重设"
    );
    Ok(Some(name.to_owned()))
}

pub fn set_default(dir: &Path, name: &str) -> Result<()> {
    load(dir, name)?.validate()?;
    let mut temp = NamedTempFile::new_in(dir)?;
    writeln!(temp, "{name}")?;
    temp.as_file().sync_all()?;
    temp.persist(dir.join(DEFAULT_PROFILE_FILE))
        .map_err(|error| error.error)
        .context("无法保存默认配置")?;
    Ok(())
}

pub fn startup_name(dir: &Path) -> Result<String> {
    let names = list(dir)?;
    if let Some(name) = default_name(dir, &names)? {
        return Ok(name);
    }
    if names.is_empty() {
        bail!("还没有配置，请打开 claude-wrapper ui 并按 N 新建");
    }
    bail!("有多个配置，请打开 claude-wrapper ui，选中一个并按 S 设为默认")
}

pub fn delete(dir: &Path, name: &str) -> Result<()> {
    let path = file(dir, name)?;
    fs::remove_file(&path).with_context(|| format!("could not delete {}", path.display()))?;
    crate::exit_pin::reset(&exit_pin_path(dir, name)?)
}

pub fn exit_pin_path(dir: &Path, name: &str) -> Result<PathBuf> {
    Ok(file(dir, name)?.with_file_name(format!("{}{name}", crate::exit_pin::PREFIX)))
}

pub fn reset_exit_pin(dir: &Path, name: &str) -> Result<()> {
    load(dir, name)?;
    crate::exit_pin::reset(&exit_pin_path(dir, name)?)?;
    crate::journal::record(dir, Some(name), "reset", crate::journal::Event::ResetPin);
    Ok(())
}

// US states and territories, with historical IANA tzdb aliases.
fn validate_us_timezone(iana: &str) -> Result<()> {
    match iana {
        "America/Los_Angeles"
        | "US/Pacific"
        | "America/Phoenix"
        | "US/Arizona"
        | "America/Denver"
        | "America/Boise"
        | "America/Shiprock"
        | "Navajo"
        | "US/Mountain"
        | "America/Chicago"
        | "America/Indiana/Knox"
        | "America/Indiana/Tell_City"
        | "America/Knox_IN"
        | "America/Menominee"
        | "America/North_Dakota/Beulah"
        | "America/North_Dakota/Center"
        | "America/North_Dakota/New_Salem"
        | "US/Central"
        | "US/Indiana-Starke"
        | "America/New_York"
        | "America/Detroit"
        | "America/Indiana/Petersburg"
        | "America/Indiana/Vincennes"
        | "America/Indiana/Winamac"
        | "America/Kentucky/Monticello"
        | "America/Kentucky/Louisville"
        | "America/Louisville"
        | "US/Eastern"
        | "US/Michigan"
        | "America/Indianapolis"
        | "America/Indiana/Indianapolis"
        | "America/Fort_Wayne"
        | "America/Indiana/Marengo"
        | "America/Indiana/Vevay"
        | "US/East-Indiana"
        | "America/Anchorage"
        | "America/Juneau"
        | "America/Metlakatla"
        | "America/Nome"
        | "America/Sitka"
        | "America/Yakutat"
        | "US/Alaska"
        | "America/Adak"
        | "America/Atka"
        | "US/Aleutian"
        | "Pacific/Honolulu"
        | "US/Hawaii"
        | "Pacific/Midway"
        | "Pacific/Pago_Pago"
        | "Pacific/Samoa"
        | "US/Samoa"
        | "America/Puerto_Rico"
        | "America/St_Thomas"
        | "America/Virgin"
        | "Pacific/Guam"
        | "Pacific/Saipan"
        | "Pacific/Wake" => Ok(()),
        _ => {
            bail!("use an IANA time zone for a US state or territory, such as America/Los_Angeles")
        }
    }
}

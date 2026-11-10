//! Terminal-only configuration workspace. Claude runs only after an explicit handoff.
use crate::journal::{self, Category};
use crate::profile::{self, ExitIp, NetworkMode, Profile};
use anyhow::{Context, Result, ensure};
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use std::{
    ffi::OsString,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicI32, Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub enum Outcome {
    Exit(i32),
    Launch { profile: String, target: OsString },
}
static SIGNAL: AtomicI32 = AtomicI32::new(0);
extern "C" fn on_signal(signal: i32) {
    SIGNAL.store(signal, Ordering::Relaxed);
}

struct ScreenGuard {
    old: Vec<(i32, libc::sigaction)>,
    raw: bool,
    alternate: bool,
}
impl ScreenGuard {
    fn enter() -> Result<Self> {
        let mut guard = Self {
            old: Vec::new(),
            raw: false,
            alternate: false,
        };
        SIGNAL.store(0, Ordering::Relaxed);
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = on_signal as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            ensure!(
                unsafe { libc::sigaction(signal, &action, &mut old) } == 0,
                "could not install terminal signal handler"
            );
            guard.old.push((signal, old));
        }
        enable_raw_mode()?;
        guard.raw = true;
        guard.alternate = true;
        execute!(io::stdout(), EnterAlternateScreen, Hide)?;
        Ok(guard)
    }
}
impl Drop for ScreenGuard {
    fn drop(&mut self) {
        if self.alternate {
            let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
        }
        if self.raw {
            let _ = disable_raw_mode();
        }
        let _ = io::stdout().flush();
        for (signal, old) in self.old.iter().rev() {
            unsafe {
                libc::sigaction(*signal, old, std::ptr::null_mut());
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Theme {
    base: Color,
    panel: Color,
    text: Color,
    muted: Color,
    border: Color,
    orange: Color,
    teal: Color,
    red: Color,
}
impl Theme {
    fn new() -> Self {
        if std::env::var_os("NO_COLOR").is_some() {
            return Self {
                base: Color::Reset,
                panel: Color::Reset,
                text: Color::Reset,
                muted: Color::Reset,
                border: Color::Reset,
                orange: Color::Reset,
                teal: Color::Reset,
                red: Color::Reset,
            };
        }
        Self {
            base: Color::Rgb(18, 20, 24),
            panel: Color::Rgb(26, 29, 35),
            text: Color::Rgb(227, 230, 235),
            muted: Color::Rgb(149, 157, 170),
            border: Color::Rgb(65, 73, 86),
            orange: Color::Rgb(245, 164, 99),
            teal: Color::Rgb(103, 211, 184),
            red: Color::Rgb(239, 131, 126),
        }
    }
    fn text(self) -> Style {
        Style::default().fg(self.text).bg(self.base)
    }
    fn block(self, title: &str) -> Block<'_> {
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(self.border))
            .style(Style::default().bg(self.panel).fg(self.text))
    }
}
const ZONES: [&str; 3] = ["America/Los_Angeles", "America/Chicago", "America/New_York"];
const ZONE_NAMES: [&str; 3] = [
    "US West - Los Angeles",
    "US Central - Chicago",
    "US East - New York",
];
const LABELS: [&str; 9] = [
    "Profile name",
    "Time zone",
    "Network mode",
    "VPN interface",
    "Proxy address",
    "Proxy environment variable",
    "Pinned exit IP",
    "Expected exit region",
    "Exit check interval",
];
const NETWORKS: [&str; 3] = ["VPN tunnel", "HTTP(S) proxy", "Environment proxy"];
const VPN_NETWORK: usize = 0;
const TIMEZONE_FIELD: usize = 1;
const NETWORK_FIELD: usize = 2;
const VPN_INTERFACE_FIELD: usize = 3;
const PROXY_URL_FIELD: usize = 4;
const PROXY_ENV_FIELD: usize = 5;
const EXIT_IP_FIELD: usize = 6;
const EXIT_COUNTRY_FIELD: usize = 7;
const EXIT_INTERVAL_FIELD: usize = 8;

fn random_label(prefix: &str) -> Result<String> {
    Ok(format!("{prefix}{}", &profile::new_device_id()?[..8]))
}
#[derive(Clone)]
struct Form {
    fields: Vec<String>,
    base: Profile,
    original: Option<String>,
    focus: usize,
    network: usize,
}
impl Form {
    fn new() -> Result<Self> {
        Self::from_profile(random_label("us-")?, Profile::new(ZONES[0])?, false)
    }
    fn from_profile(name: String, profile: Profile, edit: bool) -> Result<Self> {
        let network = if profile.vpn_interface.is_some() {
            0
        } else if profile.proxy_env.is_some() {
            2
        } else {
            1
        };
        let proxy = profile
            .proxy_url
            .as_deref()
            .filter(|url| crate::proxy::parse_proxy(url, false).is_ok())
            .unwrap_or("")
            .to_owned();
        let fields = vec![
            name.clone(),
            profile.timezone.clone(),
            String::new(),
            profile
                .vpn_interface
                .clone()
                .unwrap_or_else(|| "auto".into()),
            proxy,
            profile.proxy_env.clone().unwrap_or_default(),
            profile
                .expected_exit_ip
                .map(String::from)
                .unwrap_or_default(),
            profile.exit_country().to_owned(),
            profile.exit_check_interval().to_string(),
        ];
        Ok(Self {
            fields,
            base: profile,
            original: edit.then_some(name),
            focus: 0,
            network,
        })
    }
    fn result(&self) -> Result<(String, Profile)> {
        let mut value = self.base.clone();
        value.timezone = self.fields[TIMEZONE_FIELD].trim().into();
        let exit_ip = self.fields[EXIT_IP_FIELD].trim();
        value.expected_exit_ip = if exit_ip.is_empty() {
            None
        } else {
            Some(
                exit_ip
                    .parse()
                    .context("Pinned exit IP must be IPv4, IPv6, or auto")?,
            )
        };
        let country = self.fields[EXIT_COUNTRY_FIELD].trim().to_ascii_uppercase();
        value.expected_exit_country = (!country.is_empty()).then_some(country);
        value.exit_check_interval_seconds = Some(
            self.fields[EXIT_INTERVAL_FIELD]
                .parse()
                .context("Enter the exit check interval in seconds")?,
        );
        value.proxy_url = None;
        value.proxy_env = None;
        value.vpn_interface = None;
        match self.network {
            VPN_NETWORK => {
                value.network = Some(NetworkMode::ManagedVpn);
                value.vpn_interface = Some(self.fields[VPN_INTERFACE_FIELD].trim().into());
            }
            1 => {
                let proxy = crate::proxy::parse_proxy(self.fields[PROXY_URL_FIELD].trim(), false)?;
                value.network = Some(NetworkMode::ManagedRelay);
                value.proxy_url = Some(proxy.to_string());
            }
            _ => {
                ensure!(
                    !self.fields[PROXY_ENV_FIELD].trim().is_empty(),
                    "Enter the proxy environment variable name"
                );
                value.network = Some(NetworkMode::ManagedRelay);
                value.proxy_env = Some(self.fields[PROXY_ENV_FIELD].trim().into());
            }
        }
        value.validate()?;
        Ok((self.fields[0].trim().into(), value))
    }
    fn text(&mut self, key: KeyEvent) {
        if matches!(
            self.focus,
            NETWORK_FIELD
                | VPN_INTERFACE_FIELD
                | EXIT_IP_FIELD
                | EXIT_COUNTRY_FIELD
                | EXIT_INTERVAL_FIELD
        ) || (self.focus == 0 && self.original.is_some())
        {
            return;
        }
        let field = &mut self.fields[self.focus];
        match key.code {
            KeyCode::Backspace => {
                field.pop();
            }
            KeyCode::Char('a' | 'u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                field.clear()
            }
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                field.push(character)
            }
            _ => {}
        }
    }
}

struct VpnChoice {
    interface: Option<String>,
    label: String,
}

struct VpnPicker {
    form: Form,
    choices: Vec<VpnChoice>,
    selected: usize,
    hint: &'static str,
    manual: Option<String>,
}

impl VpnPicker {
    fn new(form: Form, discovery: Result<Vec<String>>) -> Self {
        let (interfaces, hint, current_status) = match discovery {
            Ok(interfaces) if interfaces.is_empty() => (
                interfaces,
                "No active VPN interfaces. Connect to a VPN and reopen the list.",
                "Configured, inactive",
            ),
            Ok(interfaces) => (
                interfaces,
                "Active system interfaces. Save and press H to check the exit.",
                "Configured, inactive",
            ),
            Err(_) => (
                Vec::new(),
                "Could not list interfaces. Use automatic selection or enter an interface name.",
                "Configured, status unknown",
            ),
        };
        let mut choices = vec![VpnChoice {
            interface: Some("auto".into()),
            label: "Auto-select (auto)".into(),
        }];
        choices.extend(
            interfaces
                .into_iter()
                .filter(|name| name != "auto")
                .map(|name| VpnChoice {
                    label: format!("{name} · Active"),
                    interface: Some(name),
                }),
        );
        let current = form.fields[VPN_INTERFACE_FIELD].trim();
        let selected = match choices
            .iter()
            .position(|choice| choice.interface.as_deref() == Some(current))
        {
            Some(index) => index,
            None if current.is_empty() => 0,
            None => {
                let index = choices.len();
                choices.push(VpnChoice {
                    interface: Some(current.into()),
                    label: format!("{current} · {current_status}"),
                });
                index
            }
        };
        choices.push(VpnChoice {
            interface: None,
            label: "Enter an interface name...".into(),
        });
        Self {
            form,
            choices,
            selected,
            hint,
            manual: None,
        }
    }

    fn key(mut self, key: KeyEvent) -> Mode {
        if let Some(input) = &mut self.manual {
            match key.code {
                KeyCode::Esc => self.manual = None,
                KeyCode::Enter if !input.trim().is_empty() => {
                    self.form.fields[VPN_INTERFACE_FIELD] = input.trim().into();
                    return Mode::Form(self.form);
                }
                _ => input_text(input, key),
            }
        } else {
            match key.code {
                KeyCode::Esc => return Mode::Form(self.form),
                KeyCode::Up | KeyCode::Left => self.selected = self.selected.saturating_sub(1),
                KeyCode::Down | KeyCode::Right => {
                    self.selected = (self.selected + 1).min(self.choices.len() - 1);
                }
                KeyCode::Enter => {
                    if let Some(interface) = &self.choices[self.selected].interface {
                        self.form.fields[VPN_INTERFACE_FIELD] = interface.clone();
                        return Mode::Form(self.form);
                    }
                    let current = &self.form.fields[VPN_INTERFACE_FIELD];
                    self.manual = Some(if current == "auto" {
                        String::new()
                    } else {
                        current.clone()
                    });
                }
                _ => {}
            }
        }
        Mode::VpnPicker(self)
    }
}

const IP_CHOICES: [(&str, &str); 3] = [
    ("", "Region only"),
    ("auto", "Auto-pin (default)"),
    ("manual", "Enter an IP address..."),
];
const INTERVAL_CHOICES: [(&str, &str); 6] = [
    ("15", "15 sec"),
    ("30", "30 sec"),
    ("60", "60 sec"),
    ("120", "120 sec"),
    (
        "auto",
        "Auto (default, checks more often during heavy traffic)",
    ),
    ("manual", "Custom interval..."),
];

struct ExitPicker {
    form: Form,
    selected: usize,
    search: String,
    manual: Option<String>,
    invalid_input: bool,
}

impl ExitPicker {
    fn new(form: Form) -> Self {
        let mut picker = Self {
            form,
            selected: 0,
            search: String::new(),
            manual: None,
            invalid_input: false,
        };
        let current = picker.form.fields[picker.form.focus].as_str();
        let options = picker.options();
        picker.selected = options
            .iter()
            .position(|(value, _)| *value == current)
            .or_else(|| options.iter().position(|(value, _)| *value == "manual"))
            .unwrap_or(0);
        picker
    }

    fn options(&self) -> Vec<(&'static str, &'static str)> {
        match self.form.focus {
            EXIT_IP_FIELD => return IP_CHOICES.to_vec(),
            EXIT_INTERVAL_FIELD => return INTERVAL_CHOICES.to_vec(),
            _ => {}
        }
        let needle = self.search.trim().to_lowercase();
        crate::exit_regions::choices()
            .filter(|(code, label)| {
                needle.is_empty()
                    || code.to_ascii_lowercase().starts_with(&needle)
                    || label.to_lowercase().contains(&needle)
            })
            .collect()
    }

    fn key(mut self, key: KeyEvent) -> Mode {
        if let Some(input) = &mut self.manual {
            match key.code {
                KeyCode::Esc => self.manual = None,
                KeyCode::Enter => {
                    let value = if self.form.focus == EXIT_INTERVAL_FIELD {
                        input
                            .trim()
                            .parse::<u64>()
                            .ok()
                            .filter(|seconds| profile::valid_exit_check_interval(*seconds))
                            .map(|seconds| seconds.to_string())
                    } else {
                        input
                            .trim()
                            .parse::<std::net::IpAddr>()
                            .ok()
                            .map(|ip| ip.to_string())
                    };
                    if let Some(value) = value {
                        self.form.fields[self.form.focus] = value;
                        return Mode::Form(self.form);
                    }
                    self.invalid_input = true;
                }
                _ => {
                    input_text(input, key);
                    self.invalid_input = false;
                }
            }
        } else {
            match key.code {
                KeyCode::Esc => return Mode::Form(self.form),
                KeyCode::Up => self.selected = self.selected.saturating_sub(1),
                KeyCode::Down => {
                    self.selected = (self.selected + 1).min(self.options().len().saturating_sub(1))
                }
                KeyCode::Enter => {
                    if let Some(&(value, _)) = self.options().get(self.selected) {
                        if value == "manual" {
                            let current = &self.form.fields[self.form.focus];
                            self.manual = Some(if current == "auto" {
                                String::new()
                            } else {
                                current.clone()
                            });
                            self.invalid_input = false;
                        } else {
                            self.form.fields[self.form.focus] = value.into();
                            return Mode::Form(self.form);
                        }
                    }
                }
                _ if self.form.focus == EXIT_COUNTRY_FIELD => {
                    input_text(&mut self.search, key);
                    self.selected = self
                        .options()
                        .iter()
                        .position(|(code, _)| code.eq_ignore_ascii_case(self.search.trim()))
                        .unwrap_or(0);
                }
                _ => {}
            }
        }
        Mode::ExitPicker(self)
    }
}

enum PromptKind {
    Copy(String),
    Target,
}
enum PresetTarget {
    Existing(String),
    New,
    Form(Box<Form>),
}
enum Mode {
    Home,
    Form(Form),
    VpnPicker(VpnPicker),
    ExitPicker(ExitPicker),
    Prompt {
        title: &'static str,
        kind: PromptKind,
        text: String,
    },
    Delete(String),
    ResetExitIp(String),
    Journal(JournalView),
    Preset {
        selected: usize,
        target: PresetTarget,
    },
    Help,
}

const LOG_FILTERS: [Option<Category>; 4] = [
    None,
    Some(Category::Block),
    Some(Category::Error),
    Some(Category::Exit),
];

struct JournalView {
    entries: Vec<journal::Record>,
    filter: usize,
    offset: usize,
    failed: bool,
}

impl JournalView {
    fn open(dir: &Path) -> Self {
        let records = journal::read(dir);
        Self {
            failed: records.is_err(),
            entries: records.unwrap_or_default(),
            filter: 0,
            offset: 0,
        }
    }

    fn visible(&self) -> impl Iterator<Item = &journal::Record> {
        let filter = LOG_FILTERS[self.filter];
        self.entries
            .iter()
            .rev()
            .filter(move |record| filter.is_none_or(|filter| filter == record.event.category()))
    }

    fn key(mut self, key: KeyEvent, dir: &Path) -> Mode {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q' | 'Q') => return Mode::Home,
            KeyCode::Right => {
                self.filter = (self.filter + 1) % LOG_FILTERS.len();
                self.offset = 0;
            }
            KeyCode::Left => {
                self.filter = (self.filter + LOG_FILTERS.len() - 1) % LOG_FILTERS.len();
                self.offset = 0;
            }
            KeyCode::Up => self.offset = self.offset.saturating_sub(1),
            KeyCode::Down => {
                self.offset = (self.offset + 1).min(self.visible().count().saturating_sub(1))
            }
            KeyCode::Char('r' | 'R') => {
                let filter = self.filter;
                self = Self::open(dir);
                self.filter = filter;
            }
            _ => {}
        }
        Mode::Journal(self)
    }
}

fn collector(mut reader: impl Read + Send + 'static) -> io::Result<JoinHandle<Vec<u8>>> {
    thread::Builder::new()
        .name("tui-health-output".into())
        .spawn(move || {
            let mut output = Vec::new();
            let mut buffer = [0; 4096];
            while let Ok(count) = reader.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                let keep = count.min(16384usize.saturating_sub(output.len()));
                output.extend_from_slice(&buffer[..keep]);
            }
            output
        })
}
struct HealthJob {
    child: Child,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    exited: bool,
    context: String,
    name: String,
}
impl HealthJob {
    fn start(dir: &Path, name: &str, target: &str, context: String) -> Result<Self> {
        use std::os::unix::process::CommandExt;
        let child = Command::new(std::env::current_exe()?)
            .arg("--profiles-dir")
            .arg(dir)
            .arg("doctor")
            .arg(name)
            .arg("--target")
            .arg(target)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()?;
        let mut job = Self {
            child,
            stdout: None,
            stderr: None,
            exited: false,
            context,
            name: name.into(),
        };
        let stdout = job.child.stdout.take().context("health stdout missing")?;
        job.stdout = Some(collector(stdout)?);
        let stderr = job.child.stderr.take().context("health stderr missing")?;
        job.stderr = Some(collector(stderr)?);
        Ok(job)
    }

    fn poll(&mut self) -> Result<Option<(bool, String)>> {
        let Some(status) = self.child.try_wait()? else {
            return Ok(None);
        };
        self.exited = true;
        let output = self
            .stdout
            .take()
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
        let error = self
            .stderr
            .take()
            .and_then(|handle| handle.join().ok())
            .unwrap_or_default();
        if status.success() {
            let output = String::from_utf8_lossy(&output);
            let mut message = output
                .lines()
                .find_map(|line| line.strip_prefix("exit "))
                .map_or_else(
                    || "Exit check passed".into(),
                    |result| format!("Exit {}", result.trim()),
                );
            if output.lines().any(|line| line.starts_with("api-http ")) {
                message.push_str(" · Claude API reachable");
            }
            Ok(Some((true, message)))
        } else {
            let error = String::from_utf8_lossy(&error);
            let message = if error.contains("(CN)") {
                "Blocked: Mainland China exit detected"
            } else if error.contains("GeoIP exit IP mismatch") {
                "Blocked: exit IP mismatch. Press L for details."
            } else if error.contains("automatic exit IP changed during learning") {
                "Exit IP changed between probes. Use Region only if the exit IP rotates."
            } else if error.contains("GeoIP exit country mismatch") {
                "Blocked: exit region mismatch. Press L for details."
            } else if error.contains("explicit Claude subscription OAuth credential") {
                "Blocked: custom API conflicts with subscription OAuth"
            } else if error.contains("Claude API HTTPS probe failed") {
                "Exit region matched, but the Claude API is unreachable. Check your VPN or proxy."
            } else if error.contains("timed out") {
                "Check timed out. Check your network connection."
            } else {
                "Check failed. Verify the client path, VPN or proxy, and expected region."
            };
            Ok(Some((false, message.into())))
        }
    }
}
impl Drop for HealthJob {
    fn drop(&mut self) {
        if !self.exited {
            unsafe {
                libc::kill(-(self.child.id() as i32), libc::SIGKILL);
            }
            let _ = self.child.wait();
        }
        if let Some(handle) = self.stdout.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr.take() {
            let _ = handle.join();
        }
    }
}
struct HealthRecord {
    context: String,
    name: String,
    success: bool,
    message: String,
}
struct App {
    directory: PathBuf,
    names: Vec<String>,
    default_name: Option<String>,
    selected: usize,
    mode: Mode,
    notice: String,
    working_dir: PathBuf,
    target: String,
    animate: bool,
    tick: usize,
    theme: Theme,
    health: Option<HealthJob>,
    last_health: Option<HealthRecord>,
}
impl App {
    fn new(directory: PathBuf, no_animation: bool) -> Result<Self> {
        let names = profile::list(&directory)?;
        let (default_name, notice) = match profile::default_name(&directory, &names) {
            Ok(name) => (
                name,
                "Enter launches the selected profile. Press S to make it the CLI default.".into(),
            ),
            Err(error) => (None, error.to_string()),
        };
        let selected = default_name
            .as_ref()
            .and_then(|name| names.iter().position(|item| item == name))
            .unwrap_or(0);
        Ok(Self {
            directory,
            names,
            default_name,
            selected,
            mode: Mode::Home,
            notice,
            working_dir: std::env::current_dir()?,
            target: which::which("claude")
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "claude".into()),
            animate: !no_animation && std::env::var_os("CLAUDE_WRAPPER_REDUCED_MOTION").is_none(),
            tick: 0,
            theme: Theme::new(),
            health: None,
            last_health: None,
        })
    }
    fn selected_name(&self) -> Option<&str> {
        self.names.get(self.selected).map(String::as_str)
    }
    fn context(&self) -> Option<String> {
        let name = self.selected_name()?;
        let value = profile::load(&self.directory, name).ok()?;
        Some(format!(
            "{name}\0{}\0{}",
            self.target,
            toml::to_string(&value).ok()?
        ))
    }
    fn invalidate_health(&mut self) {
        self.health = None;
        self.last_health = None;
    }
    fn reload(&mut self, preferred: Option<&str>) -> Result<()> {
        self.names = profile::list(&self.directory)?;
        self.default_name = profile::default_name(&self.directory, &self.names).unwrap_or_default();
        self.selected = preferred
            .and_then(|name| self.names.iter().position(|item| item == name))
            .unwrap_or_else(|| self.selected.min(self.names.len().saturating_sub(1)));
        self.invalidate_health();
        Ok(())
    }
    fn save_form(&mut self, form: &Form) -> Result<()> {
        let (name, value) = form.result()?;
        if let Some(original) = &form.original {
            profile::update(&self.directory, original, &value)?;
            self.notice = "Profile saved.".into();
        } else {
            profile::save(&self.directory, &name, &value)?;
            self.notice = "Profile created.".into();
        }
        self.reload(Some(&name))
    }
    fn error(&mut self, error: anyhow::Error) {
        journal::failure(&self.directory, self.selected_name(), "ui", &error);
        self.notice = format!("Failed: {error}");
    }
    fn poll_health(&mut self) {
        let completed = self.health.as_mut().and_then(|job| job.poll().transpose());
        if let Some(result) = completed {
            let job = self.health.take().expect("active health job");
            match result {
                Ok((success, message))
                    if self.context().as_deref() == Some(job.context.as_str()) =>
                {
                    self.last_health = Some(HealthRecord {
                        context: job.context.clone(),
                        name: job.name.clone(),
                        success,
                        message,
                    });
                }
                _ => {
                    self.notice =
                        "Check interrupted or profile changed. Run a new check for this profile."
                            .into();
                }
            }
        }
    }
    fn key(&mut self, key: KeyEvent) -> Result<Option<Outcome>> {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Ok(Some(Outcome::Exit(130)));
        }
        let mode = std::mem::replace(&mut self.mode, Mode::Home);
        self.mode = match mode {
            Mode::Home => match key.code {
                KeyCode::Char('q' | 'Q') => return Ok(Some(Outcome::Exit(0))),
                KeyCode::Char('?') => Mode::Help,
                KeyCode::Char('l' | 'L') => Mode::Journal(JournalView::open(&self.directory)),
                KeyCode::Char('a' | 'A') => {
                    self.animate = !self.animate;
                    Mode::Home
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.selected = self.selected.saturating_sub(1);
                    self.invalidate_health();
                    Mode::Home
                }
                KeyCode::Down => {
                    self.selected = (self.selected + 1).min(self.names.len().saturating_sub(1));
                    self.invalidate_health();
                    Mode::Home
                }
                KeyCode::Char('n' | 'N') => Mode::Form(Form::new()?),
                KeyCode::Char('e' | 'E') => {
                    if let Some(name) = self.selected_name() {
                        Mode::Form(Form::from_profile(
                            name.into(),
                            profile::load(&self.directory, name)?,
                            true,
                        )?)
                    } else {
                        self.notice = "No profiles yet. Press N to create one.".into();
                        Mode::Home
                    }
                }
                KeyCode::Char('c' | 'C') => self
                    .selected_name()
                    .map(|name| Mode::Prompt {
                        title: "Copy profile",
                        kind: PromptKind::Copy(name.into()),
                        text: format!("{name}-copy"),
                    })
                    .unwrap_or(Mode::Home),
                KeyCode::Char('d' | 'D') => self
                    .selected_name()
                    .map(|name| Mode::Delete(name.into()))
                    .unwrap_or(Mode::Home),
                KeyCode::Char('r' | 'R') => {
                    if let Some(name) = self.selected_name()
                        && matches!(
                            profile::load(&self.directory, name)?.expected_exit_ip,
                            Some(ExitIp::Auto)
                        )
                    {
                        Mode::ResetExitIp(name.into())
                    } else {
                        self.notice = "Auto-pin is disabled for this profile.".into();
                        Mode::Home
                    }
                }
                KeyCode::Char('p' | 'P') => Mode::Preset {
                    selected: 0,
                    target: self
                        .selected_name()
                        .map(|name| PresetTarget::Existing(name.into()))
                        .unwrap_or(PresetTarget::New),
                },
                KeyCode::Char('s' | 'S')
                    if key.kind == KeyEventKind::Press
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if let Some(name) = self.selected_name() {
                        profile::set_default(&self.directory, name)?;
                        self.default_name = Some(name.to_owned());
                        self.notice = "Default profile saved. Run claude-wrapper start to launch it directly.".into();
                    } else {
                        self.notice = "No profiles yet. Press N to create one.".into();
                    }
                    Mode::Home
                }
                KeyCode::Char('t' | 'T') => Mode::Prompt {
                    title: "Claude path",
                    kind: PromptKind::Target,
                    text: self.target.clone(),
                },
                KeyCode::Char('h' | 'H') => {
                    if self.health.is_none() {
                        if let (Some(name), Some(context)) = (self.selected_name(), self.context())
                        {
                            match HealthJob::start(&self.directory, name, &self.target, context) {
                                Ok(job) => {
                                    self.health = Some(job);
                                    self.last_health = None;
                                }
                                Err(error) => self.error(error),
                            }
                        } else {
                            self.notice = "Create or select a valid profile first.".into();
                        }
                    }
                    Mode::Home
                }
                KeyCode::Enter => {
                    if let Some(name) = self.selected_name() {
                        if let Ok(target) = which::which(&self.target) {
                            return Ok(Some(Outcome::Launch {
                                profile: name.into(),
                                target: target.into_os_string(),
                            }));
                        }
                        self.notice =
                            "Claude executable not found. Press T to set its path.".into();
                    } else {
                        self.notice = "No profiles yet. Press N to create one.".into();
                    }
                    Mode::Home
                }
                _ => Mode::Home,
            },
            Mode::Form(mut form) => {
                if key.code == KeyCode::Esc {
                    Mode::Home
                } else if matches!(key.code, KeyCode::Char('p' | 'P'))
                    && key.modifiers.contains(KeyModifiers::CONTROL)
                {
                    Mode::Preset {
                        selected: 0,
                        target: PresetTarget::Form(Box::new(form)),
                    }
                } else if key.code == KeyCode::Enter
                    && form.network == VPN_NETWORK
                    && form.focus == VPN_INTERFACE_FIELD
                {
                    Mode::VpnPicker(VpnPicker::new(form, crate::relay::vpn_interfaces()))
                } else if key.code == KeyCode::Enter
                    && matches!(
                        form.focus,
                        EXIT_IP_FIELD | EXIT_COUNTRY_FIELD | EXIT_INTERVAL_FIELD
                    )
                {
                    Mode::ExitPicker(ExitPicker::new(form))
                } else if key.code == KeyCode::Enter
                    || (key.code == KeyCode::Char('s')
                        && key.modifiers.contains(KeyModifiers::CONTROL))
                {
                    match self.save_form(&form) {
                        Ok(()) => Mode::Home,
                        Err(error) => {
                            self.error(error);
                            Mode::Form(form)
                        }
                    }
                } else {
                    match key.code {
                        KeyCode::Down => form.focus = (form.focus + 1) % LABELS.len(),
                        KeyCode::Up => form.focus = (form.focus + LABELS.len() - 1) % LABELS.len(),
                        KeyCode::Left if form.focus == NETWORK_FIELD => {
                            form.network = (form.network + 2) % 3
                        }
                        KeyCode::Right if form.focus == NETWORK_FIELD => {
                            form.network = (form.network + 1) % 3
                        }
                        _ => form.text(key),
                    }
                    Mode::Form(form)
                }
            }
            Mode::VpnPicker(picker) => picker.key(key),
            Mode::ExitPicker(picker) => picker.key(key),
            Mode::Journal(view) => view.key(key, &self.directory),
            Mode::Prompt {
                title,
                kind,
                mut text,
            } => match key.code {
                KeyCode::Esc => Mode::Home,
                KeyCode::Enter => {
                    let result = match &kind {
                        PromptKind::Copy(source) => (|| {
                            let mut value = profile::load(&self.directory, source)?;
                            value.device_id = Some(profile::new_device_id()?);
                            profile::save(&self.directory, &text, &value)?;
                            self.reload(Some(&text))?;
                            self.notice = "Profile copied with separate login and history.".into();
                            Ok(())
                        })(),
                        PromptKind::Target => {
                            if which::which(&text).is_ok() {
                                self.target = which::which(&text)?.to_string_lossy().into_owned();
                                self.invalidate_health();
                                self.notice = "Claude path updated.".into();
                                Ok(())
                            } else {
                                Err(anyhow::anyhow!("Executable not found"))
                            }
                        }
                    };
                    match result {
                        Ok(()) => Mode::Home,
                        Err(error) => {
                            self.error(error);
                            Mode::Prompt { title, kind, text }
                        }
                    }
                }
                _ => {
                    input_text(&mut text, key);
                    Mode::Prompt { title, kind, text }
                }
            },
            Mode::Delete(name) => match key.code {
                KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
                    match profile::delete(&self.directory, &name) {
                        Ok(()) => {
                            self.reload(None)?;
                            self.notice =
                                "Profile deleted. Claude login and history were kept. Use a new name to create another profile."
                                    .into();
                        }
                        Err(error) => self.error(error),
                    }
                    Mode::Home
                }
                KeyCode::Esc | KeyCode::Char('n' | 'N') => Mode::Home,
                _ => Mode::Delete(name),
            },
            Mode::ResetExitIp(name) => match key.code {
                KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
                    self.invalidate_health();
                    profile::reset_exit_pin(&self.directory, &name)?;
                    self.notice =
                        "Pinned IP cleared. Launch again or press H to learn a new IP.".into();
                    Mode::Home
                }
                KeyCode::Esc | KeyCode::Char('n' | 'N') => Mode::Home,
                _ => Mode::ResetExitIp(name),
            },
            Mode::Preset {
                mut selected,
                target,
            } => match key.code {
                KeyCode::Up | KeyCode::Left => {
                    selected = selected.saturating_sub(1);
                    Mode::Preset { selected, target }
                }
                KeyCode::Down | KeyCode::Right => {
                    selected = (selected + 1).min(2);
                    Mode::Preset { selected, target }
                }
                KeyCode::Esc => match target {
                    PresetTarget::Form(form) => Mode::Form(*form),
                    _ => Mode::Home,
                },
                KeyCode::Enter => match target {
                    PresetTarget::Form(mut form) => {
                        form.fields[TIMEZONE_FIELD] = ZONES[selected].into();
                        form.base.locale = "en_US.UTF-8".into();
                        Mode::Form(*form)
                    }
                    PresetTarget::New => {
                        let mut form = Form::new()?;
                        form.fields[TIMEZONE_FIELD] = ZONES[selected].into();
                        Mode::Form(form)
                    }
                    PresetTarget::Existing(name) => {
                        let result = (|| {
                            let mut value = profile::load(&self.directory, &name)?;
                            value.timezone = ZONES[selected].into();
                            value.locale = "en_US.UTF-8".into();
                            profile::update(&self.directory, &name, &value)?;
                            self.reload(Some(&name))?;
                            Ok(())
                        })();
                        match result {
                            Ok(()) => {
                                self.notice =
                                    format!("Applied the {} preset.", ZONE_NAMES[selected])
                            }
                            Err(error) => self.error(error),
                        }
                        Mode::Home
                    }
                },
                _ => Mode::Preset { selected, target },
            },
            Mode::Help => Mode::Home,
        };
        Ok(None)
    }
}
fn input_text(text: &mut String, key: KeyEvent) {
    match key.code {
        KeyCode::Backspace => {
            text.pop();
        }
        KeyCode::Char('a' | 'u') if key.modifiers.contains(KeyModifiers::CONTROL) => text.clear(),
        KeyCode::Char(c)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            text.push(c)
        }
        _ => {}
    }
}
fn safe_proxy(value: &str) -> String {
    crate::proxy::parse_proxy(value, false)
        .map(|url| url.to_string())
        .unwrap_or_else(|_| {
            "[Invalid or contains credentials. Use a proxy environment variable.]".into()
        })
}
// Rendering only: keep full values in state and when editing.
fn single_line_tail(value: &str, width: usize) -> String {
    let text = value
        .chars()
        .map(|c| if c.is_control() { '�' } else { c })
        .collect::<String>();
    if Span::raw(&text).width() <= width {
        return text;
    }
    if width == 0 {
        return String::new();
    }
    let mut tail = String::new();
    for character in text.chars().rev() {
        let candidate = format!("{character}{tail}");
        if Span::raw(&candidate).width() > width - 1 {
            break;
        }
        tail = candidate;
    }
    format!("…{tail}")
}

fn popup(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

fn vpn_name(interface: &str) -> &str {
    if interface == "auto" {
        "Auto-select"
    } else {
        interface
    }
}

fn render_vpn_picker(frame: &mut Frame<'_>, area: Rect, theme: Theme, picker: &VpnPicker) {
    if let Some(input) = &picker.manual {
        let rect = popup(area, 66, 8);
        frame.render_widget(Clear, rect);
        let lines = vec![
            Line::from("Enter a system interface name, such as utun6."),
            Line::from(""),
            Line::from(single_line_tail(
                &format!("{input}▏"),
                rect.width.saturating_sub(2) as usize,
            )),
            Line::from("Ctrl+A Clear · Enter Apply · Esc Back to list"),
        ];
        frame.render_widget(
            Paragraph::new(lines).block(theme.block(" Enter VPN interface ")),
            rect,
        );
        return;
    }

    let rect = popup(area, 68, 15);
    frame.render_widget(Clear, rect);
    let block = theme.block(" Select VPN interface ");
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(inner);
    frame.render_widget(
        Paragraph::new(picker.hint)
            .wrap(Wrap { trim: false })
            .style(Style::default().fg(theme.muted)),
        rows[0],
    );
    let entries = picker.choices.iter().map(|choice| {
        ListItem::new(single_line_tail(
            &choice.label,
            inner.width.saturating_sub(2) as usize,
        ))
    });
    let mut state = ListState::default().with_selected(Some(picker.selected));
    frame.render_stateful_widget(
        List::new(entries).highlight_symbol("› ").highlight_style(
            Style::default()
                .fg(theme.orange)
                .add_modifier(Modifier::BOLD),
        ),
        rows[1],
        &mut state,
    );
    frame.render_widget(
        Paragraph::new("↑/↓ Select · Enter Apply · Esc Back to form")
            .style(Style::default().fg(theme.orange)),
        rows[2],
    );
}

fn render_exit_picker(frame: &mut Frame<'_>, area: Rect, theme: Theme, picker: &ExitPicker) {
    let interval = picker.form.focus == EXIT_INTERVAL_FIELD;
    if let Some(input) = &picker.manual {
        let rect = popup(area, 76, 9);
        frame.render_widget(Clear, rect);
        let (hint, color) = if interval {
            (
                format!(
                    "Enter a whole number from {} to {} seconds.",
                    profile::MIN_EXIT_CHECK_INTERVAL,
                    profile::MAX_EXIT_CHECK_INTERVAL
                ),
                if picker.invalid_input {
                    theme.red
                } else {
                    theme.muted
                },
            )
        } else if picker.invalid_input {
            (
                "Invalid address. Enter an IPv4 or IPv6 address.".into(),
                theme.red,
            )
        } else {
            (
                "Enter or paste the expected public IPv4 or IPv6 address.".into(),
                theme.muted,
            )
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(single_line_tail(
                    &format!("{input}▏"),
                    rect.width.saturating_sub(2) as usize,
                )),
                Line::from(Span::styled(hint, Style::default().fg(color))),
                Line::from("Ctrl+A Clear · Enter Apply · Esc Back"),
            ])
            .block(theme.block(if interval {
                " Custom check interval "
            } else {
                " Enter exit IP "
            })),
            rect,
        );
        return;
    }

    let region = picker.form.focus == EXIT_COUNTRY_FIELD;
    let rect = popup(
        area,
        76,
        if region {
            18
        } else if interval {
            10
        } else {
            8
        },
    );
    frame.render_widget(Clear, rect);
    let title = if region {
        " Select exit region "
    } else if interval {
        " Select check interval "
    } else {
        " Select exit IP policy "
    };
    let block = theme.block(title);
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(block.inner(rect));
    frame.render_widget(block, rect);
    let hint = if region {
        format!("Search by code or name  {}▏", picker.search)
    } else if interval {
        "Checks during managed VPN or proxy sessions".into()
    } else {
        "Choose how to verify the exit IP".into()
    };
    frame.render_widget(
        Paragraph::new(single_line_tail(&hint, rows[0].width as usize))
            .style(Style::default().fg(theme.muted)),
        rows[0],
    );
    let options = picker.options();
    if options.is_empty() {
        frame.render_widget(
            Paragraph::new("No matching region. Use Backspace or Ctrl+A to clear the search."),
            rows[1],
        );
    } else {
        let items = options.iter().map(|(value, label)| {
            ListItem::new(if region {
                format!("{value}  {label}")
            } else {
                (*label).into()
            })
        });
        let list = List::new(items).highlight_symbol("› ").highlight_style(
            Style::default()
                .fg(theme.orange)
                .add_modifier(Modifier::BOLD),
        );
        let mut state = ListState::default().with_selected(Some(picker.selected));
        frame.render_stateful_widget(list, rows[1], &mut state);
    }
    frame.render_widget(
        Paragraph::new("↑/↓ Select · Enter Apply · Esc Back")
            .style(Style::default().fg(theme.muted)),
        rows[2],
    );
}

fn log_time(unix_time: u64) -> String {
    let Ok(seconds) = libc::time_t::try_from(unix_time) else {
        return "—".into();
    };
    let mut time: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&seconds, &mut time) }.is_null() {
        return "—".into();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        time.tm_year + 1900,
        time.tm_mon + 1,
        time.tm_mday,
        time.tm_hour,
        time.tm_min,
        time.tm_sec
    )
}

fn render_journal(frame: &mut Frame<'_>, area: Rect, theme: Theme, view: &JournalView) {
    let rect = popup(area, 108, 22);
    frame.render_widget(Clear, rect);
    let block = theme.block(" Wrapper Logs · UTC ");
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(block.inner(rect));
    frame.render_widget(block, rect);
    let tabs = LOG_FILTERS
        .iter()
        .enumerate()
        .map(|(index, category)| {
            let label = category.map_or("All", Category::label);
            let style = if index == view.filter {
                Style::default().fg(theme.teal).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.muted)
            };
            Span::styled(format!(" {label} "), style)
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(Line::from(tabs)), rows[0]);
    let width = rows[1].width.saturating_sub(1) as usize;
    let items = view
        .visible()
        .skip(view.offset)
        .take(usize::from(rows[1].height / 2))
        .map(|record| {
            let category = record.event.category();
            let color = match category {
                Category::Block => theme.red,
                Category::Error => theme.orange,
                Category::Exit => theme.teal,
            };
            let label = format!(
                "{}  [{}] {} · {}",
                log_time(record.unix_time),
                category.label(),
                record.operation,
                record.profile.as_deref().unwrap_or("—")
            );
            ListItem::new(vec![
                Line::from(Span::styled(
                    single_line_tail(&label, width),
                    Style::default().fg(color),
                )),
                Line::from(single_line_tail(&record.event.summary(), width)),
            ])
        })
        .collect::<Vec<_>>();
    if items.is_empty() {
        let text = if view.failed {
            "Could not read the logs."
        } else {
            "No entries in this category."
        };
        frame.render_widget(Paragraph::new(text), rows[1]);
    } else {
        frame.render_widget(List::new(items), rows[1]);
    }
    frame.render_widget(
        Paragraph::new("←/→ Category · ↑/↓ Scroll · R Refresh · Esc Back")
            .style(Style::default().fg(theme.muted)),
        rows[2],
    );
}

fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let t = app.theme;
    frame.render_widget(Block::default().style(t.text()), area);
    if area.width < 60 || area.height < 18 {
        frame.render_widget(
            Paragraph::new("Resize to at least 60 x 18. Ctrl+C quits.").style(t.text()),
            area,
        );
        return;
    }
    let rows = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(2),
        Constraint::Length(2),
    ])
    .split(area);
    let pulse = if app.animate && app.tick % 2 == 0 {
        "●"
    } else {
        "◌"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(format!(" {pulse} "), Style::default().fg(t.orange)),
            Span::styled(
                "Claude Wrapper",
                Style::default().fg(t.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  /  Profiles / Exit checks", Style::default().fg(t.muted)),
        ]))
        .block(t.block(" CLAUDE WRAPPER ")),
        rows[0],
    );
    let columns = Layout::horizontal([Constraint::Length(24), Constraint::Min(25)]).split(rows[1]);
    let items = app
        .names
        .iter()
        .map(|name| {
            let marker = if app.default_name.as_ref() == Some(name) {
                "★ "
            } else {
                "  "
            };
            ListItem::new(Line::from(vec![
                Span::styled(marker, Style::default().fg(t.teal)),
                Span::raw(name.as_str()),
            ]))
        })
        .collect::<Vec<_>>();
    let mut selected = ListState::default();
    if !app.names.is_empty() {
        selected.select(Some(app.selected));
    }
    frame.render_stateful_widget(
        List::new(items)
            .block(t.block(" Profiles (* default) "))
            .highlight_symbol("› ")
            .highlight_style(Style::default().fg(t.orange).add_modifier(Modifier::BOLD)),
        columns[0],
        &mut selected,
    );
    let mut detail = Vec::new();
    if let Some(name) = app.selected_name() {
        if let Ok(value) = profile::load(&app.directory, name)
            && value.validate().is_ok()
        {
            detail.extend([
                Line::from(format!("Time zone  {}", value.timezone)),
                Line::from(format!("Locale  {}", value.locale)),
            ]);
            let network = if let Some(vpn) = value.vpn_interface.as_deref() {
                format!("VPN · {}", vpn_name(vpn))
            } else if let Some(variable) = value.proxy_env.as_deref() {
                format!("Proxy environment variable · {variable}")
            } else {
                value
                    .proxy_url
                    .as_deref()
                    .map(safe_proxy)
                    .unwrap_or_else(|| "Not set".into())
            };
            detail.push(Line::from(format!("Network  {network}")));
            detail.push(Line::from(format!(
                "Expected exit region  {}",
                value.exit_country()
            )));
            let interval = value.exit_check_interval();
            let interval_label = if interval.is_auto() {
                format!(
                    "Auto (about {}-{} sec)",
                    profile::AUTO_MIN_SECONDS,
                    profile::AUTO_IDLE_SECONDS
                )
            } else {
                format!("{interval} sec")
            };
            detail.push(Line::from(format!("Check interval  {interval_label}")));
            match value.expected_exit_ip {
                Some(ExitIp::Fixed(ip)) => detail.push(Line::from(format!("Pinned exit  {ip}"))),
                Some(ExitIp::Auto) => {
                    let pin = profile::exit_pin_path(&app.directory, name)
                        .and_then(|path| crate::exit_pin::read(&path));
                    let status = match pin {
                        Ok(Some(ip)) => format!("Pinned {ip}"),
                        Ok(None) => "Pending".into(),
                        Err(_) => "Unreadable. Press R to reset.".into(),
                    };
                    detail.push(Line::from(format!("Auto-pinned IP  {status}")));
                }
                None => {}
            }
        } else {
            detail.push(Line::from("Invalid profile. Check the profile file."));
        }
    } else {
        detail.extend([
            Line::from("No profiles yet."),
            Line::from("N creates a profile. P opens US presets."),
        ]);
    }
    let detail_block = t.block(" Profile details ");
    let inner = detail_block.inner(columns[1]);
    frame.render_widget(detail_block, columns[1]);
    let detail_rows = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(2),
    ])
    .split(inner);
    frame.render_widget(
        Paragraph::new(detail).wrap(Wrap { trim: false }),
        detail_rows[0],
    );
    let width = inner.width as usize;
    frame.render_widget(
        Paragraph::new(format!(
            "Directory  {}",
            single_line_tail(&app.working_dir.to_string_lossy(), width.saturating_sub(10))
        ))
        .style(Style::default().fg(t.muted)),
        detail_rows[1],
    );
    frame.render_widget(
        Paragraph::new(format!(
            "Client  {}",
            single_line_tail(&app.target, width.saturating_sub(6))
        ))
        .style(Style::default().fg(t.muted)),
        detail_rows[2],
    );
    let health_line = if let Some(job) = &app.health {
        let icons = ["⠋", "⠙", "⠹", "⠸"];
        Line::from(Span::styled(
            format!(
                "{} Current check · {}",
                if app.animate {
                    icons[app.tick % 4]
                } else {
                    "…"
                },
                single_line_tail(&job.name, 12)
            ),
            Style::default().fg(t.teal),
        ))
    } else if let Some(record) = &app.last_health
        && app.context().as_deref() == Some(record.context.as_str())
    {
        Line::from(Span::styled(
            format!(
                "Last check · {} · {}",
                single_line_tail(&record.name, 12),
                record.message
            ),
            Style::default().fg(if record.success { t.teal } else { t.red }),
        ))
    } else {
        Line::from(Span::styled(
            "No exit check yet - H to check",
            Style::default().fg(t.muted),
        ))
    };
    frame.render_widget(
        Paragraph::new(health_line).wrap(Wrap { trim: false }),
        detail_rows[3],
    );
    frame.render_widget(
        Paragraph::new(app.notice.as_str())
            .style(Style::default().fg(t.muted))
            .wrap(Wrap { trim: false }),
        rows[2],
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(" N New E Edit C Copy D Del P Presets S Default T Client"),
            Line::from(format!(
                " H Check R Reset L Logs Enter Run ? Help A Anim {} Q Quit",
                if app.animate { "On" } else { "Off" }
            )),
        ])
        .style(Style::default().fg(t.orange)),
        rows[3],
    );
    match &app.mode {
        Mode::Home => {}
        Mode::Journal(view) => render_journal(frame, area, t, view),
        Mode::Form(form) => {
            let rect = popup(area, 88, 20);
            frame.render_widget(Clear, rect);
            let mut lines = vec![
                Line::from("↑/↓ Switch fields · Ctrl+A Clear · ←/→ Network · Ctrl+P Presets"),
                Line::from(""),
            ];
            for (index, label) in LABELS.iter().enumerate() {
                let text = if index == NETWORK_FIELD {
                    format!("‹ {} ›", NETWORKS[form.network])
                } else if index == VPN_INTERFACE_FIELD {
                    if form.network == VPN_NETWORK {
                        format!("‹ {} · Enter Select ›", vpn_name(&form.fields[index]))
                    } else {
                        "Available in VPN mode".into()
                    }
                } else if index == EXIT_IP_FIELD {
                    let mode = match form.fields[index].as_str() {
                        "" => "Region only",
                        "auto" => "Auto-pin",
                        ip => ip,
                    };
                    format!("‹ {mode} · Enter Select ›")
                } else if index == EXIT_COUNTRY_FIELD {
                    let code = form.fields[index].as_str();
                    let name = crate::exit_regions::name(code).unwrap_or("Unknown region");
                    format!("‹ {code} {name} · Enter Select ›")
                } else if index == EXIT_INTERVAL_FIELD {
                    let interval = &form.fields[index];
                    if interval == "auto" {
                        format!(
                            "‹ Auto (about {}-{} sec) · Enter Select ›",
                            profile::AUTO_MIN_SECONDS,
                            profile::AUTO_IDLE_SECONDS
                        )
                    } else {
                        format!("‹ {interval} sec · Enter Select ›")
                    }
                } else if index == PROXY_URL_FIELD && !form.fields[index].is_empty() {
                    if form.focus == PROXY_URL_FIELD {
                        "•".repeat(form.fields[index].chars().count().min(40))
                    } else {
                        safe_proxy(&form.fields[index])
                    }
                } else {
                    form.fields[index].clone()
                };
                let marker = if form.focus == index { "›" } else { " " };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!(
                            "{marker} {label}{} ",
                            " ".repeat(12usize.saturating_sub(Span::raw(*label).width()))
                        ),
                        Style::default().fg(if form.focus == index {
                            t.orange
                        } else {
                            t.muted
                        }),
                    ),
                    Span::styled(
                        single_line_tail(
                            &format!("{text}{}", if form.focus == index { "▏" } else { "" }),
                            rect.width.saturating_sub(17) as usize,
                        ),
                        Style::default().fg(t.text),
                    ),
                ]));
            }
            lines.extend([
                Line::from(""),
                Line::from("Press Enter on the VPN interface, region, IP, or interval field."),
                Line::from("The proxy address is hidden while editing. Move to another field to reveal it."),
                Line::from(Span::styled(
                    app.notice.as_str(),
                    Style::default().fg(if app.notice.starts_with("Failed") {
                        t.red
                    } else {
                        t.muted
                    }),
                )),
                Line::from("Ctrl+S Save · Esc Discard"),
            ]);
            frame.render_widget(
                Paragraph::new(lines).block(t.block(if form.original.is_some() {
                    " Edit profile "
                } else {
                    " New profile "
                })),
                rect,
            );
        }
        Mode::VpnPicker(picker) => render_vpn_picker(frame, area, t, picker),
        Mode::ExitPicker(picker) => render_exit_picker(frame, area, t, picker),
        Mode::Prompt { title, text, .. } => {
            let rect = popup(area, 82, 9);
            frame.render_widget(Clear, rect);
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from("Ctrl+A clears the field. Enter the path without quotes."),
                    Line::from(""),
                    Line::from(single_line_tail(
                        &format!("{text}▏"),
                        rect.width.saturating_sub(2) as usize,
                    )),
                    Line::from(app.notice.as_str()),
                    Line::from("Enter Confirm · Esc Back"),
                ])
                .wrap(Wrap { trim: false })
                .block(t.block(title)),
                rect,
            );
        }
        Mode::Delete(name) => {
            let rect = popup(area, 74, 9);
            frame.render_widget(Clear, rect);
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(format!("Delete profile {name}?")),
                    Line::from("Claude login, history, and project files are kept."),
                    Line::from("Use a new name when creating another profile."),
                    Line::from(""),
                    Line::from("Y / Enter Delete · N / Esc Cancel"),
                ])
                .block(t.block(" Delete profile ")),
                rect,
            );
        }
        Mode::ResetExitIp(name) => {
            let rect = popup(area, 74, 7);
            frame.render_widget(Clear, rect);
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from(format!("Clear the pinned exit IP for {name}?")),
                    Line::from("On launch or H, three matching probes pin the exit IP again."),
                    Line::from("Y / Enter Confirm · Esc Cancel"),
                ])
                .block(t.block(" Reset pinned exit IP ")),
                rect,
            );
        }
        Mode::Preset { selected, .. } => {
            let rect = popup(area, 68, 10);
            frame.render_widget(Clear, rect);
            let mut lines = vec![
                Line::from("Apply the selected time zone and locale."),
                Line::from(""),
            ];
            for (index, name) in ZONE_NAMES.iter().enumerate() {
                lines.push(Line::from(Span::styled(
                    format!("{} {name}", if index == *selected { "›" } else { " " }),
                    Style::default().fg(if index == *selected { t.orange } else { t.text }),
                )));
            }
            lines.extend([
                Line::from(""),
                Line::from("↑/↓ Select · Enter Apply · Esc Back"),
            ]);
            frame.render_widget(Paragraph::new(lines).block(t.block(" US presets ")), rect);
        }
        Mode::Help => {
            let rect = popup(area, 82, 19);
            frame.render_widget(Clear, rect);
            frame.render_widget(Paragraph::new("Up/Down Select a profile. Enter Launch.\nS Set default for claude-wrapper start.\nN New · E Edit · C Copy · D Delete\nP Open US presets. In the editor, use Ctrl+P.\nT Set the Claude executable.\nH Check exit · R Reset pinned IP · L Browse logs\nPress H to recheck after editing a profile.\nUp/Down Switch fields. Ctrl+A Clear. Ctrl+S Save.\nEnter opens VPN and exit options.\nA Toggle motion. Use ui --no-animation or CLAUDE_WRAPPER_REDUCED_MOTION to reduce motion.\nNO_COLOR disables colors. Ctrl+C or Q quits.\nPress any key to return.").wrap(Wrap{trim:false}).block(t.block(" Help ")),rect);
        }
    }
}

pub fn run(directory: PathBuf, no_animation: bool) -> Result<Outcome> {
    let _screen = ScreenGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut app = App::new(directory, no_animation)?;
    let mut last_tick = Instant::now();
    let mut dirty = true;
    loop {
        let signal = SIGNAL.load(Ordering::Relaxed);
        if signal != 0 {
            return Ok(Outcome::Exit(128 + signal));
        }
        let checking = app.health.is_some();
        app.poll_health();
        if checking && app.health.is_none() {
            dirty = true;
        }
        let interval = if app.health.is_some() {
            Duration::from_millis(200)
        } else {
            Duration::from_millis(900)
        };
        if app.animate && last_tick.elapsed() >= interval {
            app.tick = app.tick.wrapping_add(1);
            last_tick = Instant::now();
            dirty = true;
        }
        if dirty {
            terminal.draw(|frame| render(frame, &app))?;
            dirty = false;
        }
        match event::poll(Duration::from_millis(100)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key))
                    if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) =>
                {
                    dirty = true;
                    match app.key(key) {
                        Ok(Some(outcome)) => return Ok(outcome),
                        Ok(None) => {}
                        Err(error) => {
                            app.error(error);
                            app.mode = Mode::Home;
                        }
                    }
                }
                Ok(Event::Resize(..)) => dirty = true,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            },
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn drafts_have_independent_identities_and_do_not_save_secrets() {
        let a = Form::new().unwrap();
        let b = Form::new().unwrap();
        assert_ne!(a.base.device_id, b.base.device_id);
        let mut bad = a.clone();
        bad.network = 1;
        bad.fields[PROXY_URL_FIELD] = "http://user:secret@127.0.0.1:8080".into();
        assert!(bad.result().is_err());
        bad.network = 2;
        bad.fields[PROXY_ENV_FIELD] = "MY_PROXY".into();
        let (_, value) = bad.result().unwrap();
        assert_eq!(value.proxy_env.as_deref(), Some("MY_PROXY"));
        assert!(value.proxy_url.is_none());
    }
    #[test]
    fn editing_keeps_id_and_client_state_while_copy_uses_a_new_id() {
        let root = tempfile::tempdir().unwrap();
        let original = Profile::new(ZONES[0]).unwrap();
        profile::save(root.path(), "qa-west", &original).unwrap();
        let state = root.path().join("clients/qa-west");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("marker"), "keep").unwrap();
        let mut changed = original.clone();
        changed.timezone = ZONES[2].into();
        changed.device_id = Some("f".repeat(64));
        profile::update(root.path(), "qa-west", &changed).unwrap();
        let edited = profile::load(root.path(), "qa-west").unwrap();
        assert_eq!(edited.device_id, original.device_id);
        assert_eq!(fs::read_to_string(state.join("marker")).unwrap(), "keep");
        let mut copied = edited.clone();
        copied.device_id = Some(profile::new_device_id().unwrap());
        profile::save(root.path(), "qa-copy", &copied).unwrap();
        assert_ne!(copied.device_id, edited.device_id);
        profile::delete(root.path(), "qa-west").unwrap();
        assert!(state.join("marker").is_file());
        assert!(profile::save(root.path(), "qa-west", &copied).is_err());
    }
    #[test]
    fn damaged_unicode_device_id_renders_invalid_state_at_80_by_24() {
        let root = tempfile::tempdir().unwrap();
        let mut value = Profile::new(ZONES[0]).unwrap();
        value.device_id = Some("abc😀😀😀".into());
        fs::write(
            root.path().join("qa-broken.toml"),
            toml::to_string(&value).unwrap(),
        )
        .unwrap();
        let app = App::new(root.path().to_owned(), true).unwrap();
        let backend = ratatui::backend::TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.replace(' ', "").contains("Invalidprofile"));
    }
    #[test]
    fn narrow_screen_keeps_health_visible_with_long_unicode_paths() {
        let root = tempfile::tempdir().unwrap();
        let mut app = App::new(root.path().to_owned(), true).unwrap();
        app.working_dir = format!("/tmp/{}/project", "很长的项目路径/".repeat(20)).into();
        app.target = format!("/tmp/{}/claude", "very long client path/".repeat(20));
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.replace(' ', "").contains("Noexitcheckyet"));
        assert!(!text.contains(&app.target));
        let shortened = single_line_tail("abc😀😀😀/文件名", 10);
        assert!(Span::raw(&shortened).width() <= 10);
    }
    #[test]
    fn invalid_edit_does_not_replace_existing_profile() {
        let root = tempfile::tempdir().unwrap();
        let value = Profile::new(ZONES[0]).unwrap();
        let path = profile::save(root.path(), "qa-west", &value).unwrap();
        let before = fs::read(&path).unwrap();
        let mut bad = value;
        bad.timezone = "Asia/Shanghai".into();
        assert!(profile::update(root.path(), "qa-west", &bad).is_err());
        assert_eq!(fs::read(path).unwrap(), before);
    }

    #[test]
    fn vpn_picker_preserves_inactive_profile_until_selection_is_saved() {
        let root = tempfile::tempdir().unwrap();
        let mut profile = Profile::new(ZONES[0]).unwrap();
        profile.vpn_interface = Some("utun90".into());
        profile::save(root.path(), "qa-vpn", &profile).unwrap();
        let mut form = Form::from_profile("qa-vpn".into(), profile, true).unwrap();
        form.focus = VPN_INTERFACE_FIELD;
        let mut app = App::new(root.path().to_owned(), true).unwrap();
        app.mode = Mode::VpnPicker(VpnPicker::new(
            form,
            Ok(vec!["utun2".into(), "utun6".into()]),
        ));

        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
            .replace(' ', "");
        assert!(text.contains("Auto-select(auto)"));
        assert!(text.contains("utun6·Active"));
        assert!(text.contains("utun90·Configured,inactive"));

        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        app.key(press(KeyCode::Up)).unwrap();
        app.key(press(KeyCode::Enter)).unwrap();
        let Mode::Form(form) = &app.mode else {
            panic!("selection should return to the draft form");
        };
        assert_eq!(form.fields[VPN_INTERFACE_FIELD], "utun6");
        let saved_interface = || profile::load(root.path(), "qa-vpn").unwrap().vpn_interface;
        assert_eq!(saved_interface().as_deref(), Some("utun90"));
        app.key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL))
            .unwrap();
        assert_eq!(saved_interface().as_deref(), Some("utun6"));
    }

    #[test]
    fn vpn_picker_manual_input_works_without_detected_interfaces() {
        let mut form = Form::new().unwrap();
        form.focus = VPN_INTERFACE_FIELD;
        let picker = VpnPicker::new(form, Ok(Vec::new()));
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let Mode::VpnPicker(picker) = picker.key(press(KeyCode::Down)) else {
            panic!("manual option should remain selectable");
        };
        let Mode::VpnPicker(picker) = picker.key(press(KeyCode::Enter)) else {
            panic!("manual option should open its input");
        };
        assert_eq!(picker.manual.as_deref(), Some(""));
        let mut picker = picker;
        for character in "ppp4".chars() {
            let Mode::VpnPicker(updated) = picker.key(press(KeyCode::Char(character))) else {
                panic!("manual typing should keep the interface editor open");
            };
            picker = updated;
        }
        let Mode::Form(form) = picker.key(press(KeyCode::Enter)) else {
            panic!("confirmed manual input should return to the form");
        };
        assert_eq!(
            form.result().unwrap().1.vpn_interface.as_deref(),
            Some("ppp4")
        );
    }
}

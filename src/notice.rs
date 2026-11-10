use std::{
    env, fmt,
    io::{self, IsTerminal},
};

pub enum Level {
    Exit,
    Warning,
    Blocked,
    Error,
}

pub fn emit(level: Level, message: fmt::Arguments<'_>) {
    let (label, color) = match level {
        Level::Exit => ("出口", 32),
        Level::Warning => ("提示", 33),
        Level::Blocked => ("拦截", 31),
        Level::Error => ("错误", 31),
    };
    if io::stderr().is_terminal()
        && env::var_os("NO_COLOR").is_none()
        && !env::var_os("TERM").is_some_and(|value| value == "dumb")
    {
        eprintln!("\x1b[1;{color}m[Wrapper/{label}]\x1b[0m: {message}");
    } else {
        eprintln!("[Wrapper/{label}]: {message}");
    }
}

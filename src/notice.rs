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
        Level::Exit => ("Exit", 32),
        Level::Warning => ("Warning", 33),
        Level::Blocked => ("Blocked", 31),
        Level::Error => ("Error", 31),
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

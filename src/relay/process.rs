//! Own one process group while retaining its leader until group cleanup completes.
use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{fs::OpenOptionsExt, process::CommandExt},
    },
    process::{Child, Command, ExitStatus},
    time::Duration,
};

use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::{Instant, sleep},
};

const TERMINATION_GRACE: Duration = Duration::from_secs(2);

struct Terminal {
    file: File,
    parent_group: libc::pid_t,
    child_group: libc::pid_t,
}

impl Terminal {
    fn open(child_group: libc::pid_t) -> io::Result<Option<Self>> {
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
            .open("/dev/tty")
        {
            Ok(file) => file,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENXIO | libc::ENODEV | libc::ENOTTY)
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if unsafe { libc::tcgetpgrp(file.as_raw_fd()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(Some(Self {
            file,
            parent_group: unsafe { libc::getpgrp() },
            child_group,
        }))
    }

    fn set_foreground(&self, group: libc::pid_t) -> io::Result<()> {
        unsafe {
            // The wrapper is in the background while its child owns the terminal.
            let mut blocked: libc::sigset_t = std::mem::zeroed();
            let mut previous: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, libc::SIGTTOU);
            let result = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous);
            if result != 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
            let changed = libc::tcsetpgrp(self.file.as_raw_fd(), group);
            let error = io::Error::last_os_error();
            let restored =
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
            if changed == -1 {
                return Err(error);
            }
            if restored != 0 {
                return Err(io::Error::from_raw_os_error(restored));
            }
            Ok(())
        }
    }

    fn give_to_child(&self) -> io::Result<()> {
        if unsafe { libc::tcgetpgrp(self.file.as_raw_fd()) } == self.parent_group {
            self.set_foreground(self.child_group)?;
        }
        Ok(())
    }

    fn restore(&self) -> io::Result<()> {
        if unsafe { libc::tcgetpgrp(self.file.as_raw_fd()) } == self.child_group {
            self.set_foreground(self.parent_group)?;
        }
        Ok(())
    }
}

pub(super) struct ChildGroup {
    child: Child,
    group: libc::pid_t,
    changes: Signal,
    terminal: Option<Terminal>,
    reaped: bool,
}

impl ChildGroup {
    pub(super) fn spawn(mut command: Command) -> io::Result<Self> {
        let changes = signal(SignalKind::child())?;
        command.process_group(0);
        let child = command.spawn()?;
        let group = child.id() as libc::pid_t;
        let mut owned = Self {
            child,
            group,
            changes,
            terminal: None,
            reaped: false,
        };
        owned.terminal = Terminal::open(group)?;
        if let Some(terminal) = &owned.terminal {
            terminal.give_to_child()?;
            // A fast terminal reader may have stopped before the foreground handoff.
            owned.send(libc::SIGCONT)?;
        }
        Ok(owned)
    }

    pub(super) fn id(&self) -> u32 {
        self.child.id()
    }

    fn send(&self, number: i32) -> io::Result<()> {
        if unsafe { libc::kill(-self.group, number) } == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EPERM)
                && self.exited()?
                && !self.has_other_members()
            {
                return Ok(());
            }
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    fn event(&self, options: i32) -> io::Result<libc::siginfo_t> {
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut info,
                    options | libc::WNOHANG,
                )
            };
            if result == 0 {
                return Ok(info);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn exited(&self) -> io::Result<bool> {
        let info = self.event(libc::WEXITED | libc::WNOWAIT)?;
        Ok(info.si_pid != 0)
    }

    pub(super) async fn wait_for_exit(&mut self) -> io::Result<()> {
        loop {
            let info =
                self.event(libc::WEXITED | libc::WSTOPPED | libc::WCONTINUED | libc::WNOWAIT)?;
            match info.si_code {
                libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED if info.si_pid != 0 => {
                    return Ok(());
                }
                libc::CLD_STOPPED | libc::CLD_TRAPPED if info.si_pid != 0 => {
                    // Consume only job-control events; the leader's exit remains unreaped.
                    self.event(libc::WSTOPPED | libc::WCONTINUED)?;
                    if let Some(terminal) = &self.terminal {
                        terminal.restore()?;
                    }
                    unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
                    if let Some(terminal) = &self.terminal {
                        terminal.give_to_child()?;
                    }
                    self.send(libc::SIGCONT)?;
                }
                libc::CLD_CONTINUED if info.si_pid != 0 => {
                    self.event(libc::WSTOPPED | libc::WCONTINUED)?;
                }
                _ => {
                    self.changes.recv().await;
                }
            }
        }
    }

    fn has_other_members(&self) -> bool {
        // Two slots suffice: at most one entry can be the retained leader.
        let mut members = [0 as libc::pid_t; 2];
        let count = unsafe {
            *libc::__error() = 0;
            libc::proc_listpgrppids(
                self.group,
                members.as_mut_ptr().cast(),
                std::mem::size_of_val(&members) as i32,
            )
        };
        if count == 0 {
            // Kernel process lists can omit the retained zombie leader.
            return io::Error::last_os_error().raw_os_error() != Some(0);
        }
        if count < 0 {
            return true;
        }
        members[..(count as usize).min(members.len())]
            .iter()
            .any(|pid| *pid > 0 && *pid != self.group)
    }

    pub(super) async fn terminate(&mut self, number: i32) -> io::Result<ExitStatus> {
        if let Some(terminal) = &self.terminal {
            terminal.restore()?;
        }
        // Darwin returns EPERM when a process group contains only its zombie leader.
        if !self.exited()? || self.has_other_members() {
            self.send(number)?;
            self.send(libc::SIGCONT)?;
        }
        let deadline = Instant::now() + TERMINATION_GRACE;
        while Instant::now() < deadline {
            if self.exited()? && !self.has_other_members() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        // The unreaped leader reserves the group ID until all final signals are sent.
        if !self.exited()? || self.has_other_members() {
            self.send(libc::SIGKILL)?;
            let _ = self.child.kill();
        }
        let status = self.child.wait();
        self.reaped = true;
        status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a fresh controlling terminal; run tests/real_claude/pty_check.py"]
    async fn terminal_handoff_fast_exit_and_native_input() {
        assert!(unsafe { libc::isatty(libc::STDIN_FILENO) } == 1);
        let foreground = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
        for _ in 0..50 {
            let mut child = ChildGroup::spawn(Command::new("/usr/bin/true")).unwrap();
            child.wait_for_exit().await.unwrap();
            assert!(child.terminate(libc::SIGTERM).await.unwrap().success());
            assert_eq!(unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) }, foreground);
        }
        println!("PTY_NATIVE_INPUT_READY");
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "IFS= read -r reply < /dev/tty; test \"$reply\" = hello",
        ]);
        let mut child = ChildGroup::spawn(command).unwrap();
        child.wait_for_exit().await.unwrap();
        assert!(child.terminate(libc::SIGTERM).await.unwrap().success());
        assert_eq!(unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) }, foreground);
    }
}

impl Drop for ChildGroup {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.send(libc::SIGKILL);
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(terminal) = &self.terminal {
            let _ = terminal.restore();
        }
    }
}

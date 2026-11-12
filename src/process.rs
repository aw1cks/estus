//! Direct-child ownership for controller operations, not a process sandbox.
//!
//! The unreaped anchor reserves the process-group identity until the final group
//! signal. We never inspect or signal a numeric group after reaping that anchor.
use std::io::{self, Read};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};

use nix::errno::Errno;
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

pub(crate) const ANCHOR_ARG: &str = "--internal-controller-anchor";

/// Hidden synchronous helper: stdin is the parent's keepalive, never user input.
pub(crate) fn anchor() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let mut buffer = [0u8; 1024];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

#[derive(Default)]
pub(crate) struct Children {
    anchor: Option<Child>,
    keepalive: Option<ChildStdin>,
    pub(crate) script: Option<Child>,
    final_signal: bool,
    signal_ok: bool,
    reap_failed: bool,
}

impl Children {
    pub(crate) fn start_anchor(&mut self) -> io::Result<u32> {
        let child = Command::new(std::env::current_exe()?)
            .arg(ANCHOR_ARG)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()?;
        // Install ownership before inspecting any fallible setup state.
        self.anchor = Some(child);
        let anchor = self
            .anchor
            .as_mut()
            .ok_or_else(|| io::Error::other("controller anchor setup failed"))?;
        self.keepalive = anchor.stdin.take();
        if self.keepalive.is_none() {
            return Err(io::Error::other("controller anchor setup failed"));
        }
        Ok(anchor.id())
    }

    pub(crate) fn install_script(&mut self, child: Child) {
        self.script = Some(child);
    }

    pub(crate) fn script_status(&mut self) -> io::Result<Option<ExitStatus>> {
        match self.script.as_mut() {
            Some(child) => child.try_wait(),
            None => Ok(None),
        }
    }

    /// Exactly one group signal, while the anchor remains owned and unreaped.
    pub(crate) fn signal_final(&mut self) {
        if self.final_signal {
            return;
        }
        self.final_signal = true;
        self.signal_ok = match self.anchor.as_ref() {
            Some(anchor) => match i32::try_from(anchor.id()) {
                Ok(id) => matches!(
                    killpg(Pid::from_raw(id), Signal::SIGKILL),
                    Ok(()) | Err(Errno::ESRCH)
                ),
                Err(_) => false,
            },
            None => true,
        };
        // An interpreter can change its own group. Its owned Child remains safe
        // to kill; Child::kill does not signal an already-reaped numeric PID.
        if let Some(script) = self.script.as_mut() {
            let _ = script.kill();
        }
        if let Some(anchor) = self.anchor.as_mut() {
            let _ = anchor.kill();
        }
        self.keepalive.take();
    }

    pub(crate) fn reap(&mut self) -> bool {
        if !self.final_signal {
            return false;
        }
        for slot in [&mut self.script, &mut self.anchor] {
            let result = match slot.as_mut() {
                Some(child) => child.try_wait(),
                None => continue,
            };
            match result {
                Ok(Some(_)) => {
                    slot.take();
                }
                Ok(None) => {}
                Err(_) => {
                    self.reap_failed = true;
                }
            }
        }
        self.script.is_none() && self.anchor.is_none()
    }

    pub(crate) fn started(&self) -> bool {
        self.anchor.is_some() || self.final_signal
    }

    pub(crate) fn clean(&self) -> bool {
        self.final_signal
            && self.signal_ok
            && !self.reap_failed
            && self.anchor.is_none()
            && self.script.is_none()
    }
}

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(crate) use openssh::{
    Child as OpensshChild, ChildStdin, Command, Error as SshError, Session, Stdio,
};
#[cfg(unix)]
pub(crate) type Child<'s> = OpensshChild<&'s Session>;
#[cfg(unix)]
pub(crate) use unix::{Lease, MasterHealth, Pool};

#[cfg(windows)]
pub(crate) use std::process::Stdio;
#[cfg(windows)]
pub(crate) use tokio::process::ChildStdin;
#[cfg(windows)]
pub(crate) use windows::{Child, Command, Lease, MasterHealth, Pool, Session, SshError};

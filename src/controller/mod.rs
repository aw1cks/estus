#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(crate) use unix::{
    CleanupQuarantine, CleanupReservation, ControllerContext, ControllerRun, PendingCleanup,
    QUARANTINE_CAPACITY, run,
};

#[cfg(windows)]
pub(crate) use windows::{CleanupQuarantine, ControllerContext, QUARANTINE_CAPACITY, run};

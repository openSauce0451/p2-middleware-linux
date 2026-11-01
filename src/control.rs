// src/control.rs
//! Control protocol: shared types plus platform transport.

pub use crate::control_common::*;

#[cfg(windows)]
pub use crate::control_win::*;

#[cfg(not(windows))]
pub use crate::control_linux::*;

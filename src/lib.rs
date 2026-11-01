pub mod approval;
pub mod bridge;
pub mod config;
pub mod network;
pub mod request;
pub mod session;          // no longer Windows-gated

mod control_common;
pub mod control;

#[cfg(windows)]
pub mod elevation;
#[cfg(windows)]
pub mod native_gateway;
#[cfg(windows)]
pub mod route_client;
#[cfg(windows)]
pub mod windows_host;
#[cfg(windows)]
pub mod control_win;

#[cfg(not(windows))]
pub mod control_linux;
#[cfg(not(windows))]
pub mod elevation_linux;
#[cfg(not(windows))]
pub mod journal_linux;
#[cfg(not(windows))]
pub mod network_linux;
#[cfg(not(windows))]
mod route_client_linux;

#[cfg(windows)]
pub use route_client::RouteClient;
#[cfg(not(windows))]
pub use route_client_linux::RouteClient;

pub use control_common::{Command, Lines};

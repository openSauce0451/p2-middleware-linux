#[cfg(feature = "web-auth")]
pub mod auth;
pub mod channel;
pub mod gateway;
pub mod udp_relay;
pub mod ps3_tunnel;
pub mod lobby_advertisement;
pub mod lobby_diagnostics;
pub mod protocol;
pub mod stun;

pub fn bad(reason: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, reason)
}

pub mod legacy_cm;

#[cfg(target_os = "linux")]
pub mod catch_all;

#[cfg(target_os = "windows")]
pub mod win_catch_all;


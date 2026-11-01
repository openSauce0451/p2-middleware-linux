#[cfg(feature = "web-auth")]
pub mod auth;
pub mod channel;
pub mod gateway;
pub mod udp_relay;
pub mod lobby_advertisement;
pub mod lobby_diagnostics;
pub mod protocol;

pub fn bad(reason: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, reason)
}

pub mod legacy_cm;

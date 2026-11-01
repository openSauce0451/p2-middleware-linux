//! Shared helper-input contract.

use crate::config::Settings;
use serde::{Deserialize, Serialize};
use std::io;

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub settings: Settings,
    pub interface: u32,
}

impl Request {
    pub fn validate(&self) -> io::Result<()> {
        self.settings.validate().map_err(io::Error::other)?;
        if self.interface == 0 {
            return Err(io::Error::other("interface_required"));
        }
        Ok(())
    }
}

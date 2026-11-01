// src/control_common.rs
//! Shared control protocol types (cross-platform)

use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "command", content = "request", deny_unknown_fields)]
pub enum Command {
    Session,
    Reset,
    Stop,
    Start(Request),
}

impl Command {
    pub fn validate(&self) -> io::Result<()> {
        match self {
            Self::Start(request) => request.validate(),
            _ => Ok(()),
        }
    }
}

use crate::request::Request;

const LIMIT: usize = 16384;

/// Bounded frame reader for line-delimited JSON
#[derive(Default)]
pub struct Lines {
    pending: Vec<u8>,
}

impl Lines {
    pub async fn next(
        &mut self,
        input: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(end) = self.pending.iter().position(|b| *b == b'\n') {
                return Ok(Some(self.pending.drain(..=end).collect()));
            }
            if self.pending.len() >= LIMIT {
                return Err(io::Error::new(io::ErrorKind::Other, "control_frame_limit"));
            }
            let mut chunk = [0u8; 1024];
            let capacity = chunk.len().min(LIMIT - self.pending.len());
            let count = input.read(&mut chunk[..capacity]).await?;
            if count == 0 {
                return if self.pending.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "control_partial_frame"))
                };
            }
            self.pending.extend_from_slice(&chunk[..count]);
        }
    }
}

pub async fn send(
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
                  value: &impl Serialize,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    if bytes.len() >= LIMIT {
        return Err(io::Error::new(io::ErrorKind::Other, "control_frame_limit"));
    }
    bytes.push(b'\n');
    tokio::time::timeout(std::time::Duration::from_secs(3), output.write_all(&bytes))
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "control_write_timeout"))?
}

pub fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
}

//! One helper owner: cleanup on startup, apply on confirmation, cleanup on disconnect.
use crate::{
    control::{self, Command, Lines},
    request::Request,
};
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
pub trait Network {
    fn cleanup(&mut self) -> io::Result<()>;
    fn start(&mut self, request: Request) -> io::Result<()>;
    /// Periodic upkeep while active; called often, so implementations rate-limit.
    fn maintain(&mut self) {}
    fn failed(&self) -> bool;
}
async fn event(pipe: &mut (impl AsyncWrite + Unpin), name: &str) {
    // Reporting failures never prevent cleanup.
    let _ = control::send(pipe, &serde_json::json!({"event":name})).await;
}
pub async fn run(
    pipe: &mut (impl AsyncRead + AsyncWrite + Unpin),
    mut lines: Lines,
    host: &mut impl Network,
) -> Result<(), &'static str> {
    event(pipe, "restoring").await;
    host.cleanup().map_err(|_| "recovery_incomplete")?;
    event(pipe, "session_clean").await;
    let mut active = false;
    loop {
        if active {
            host.maintain();
        }
        if host.failed() {
            event(pipe, "restoring").await;
            host.cleanup().map_err(|_| "recovery_incomplete")?;
            active = false;
            event(pipe, "session_clean").await;
        }
        let line = match tokio::time::timeout(Duration::from_millis(100), lines.next(pipe)).await {
            Err(_) => continue,
            Ok(Ok(Some(line))) => line,
            _ => break,
        };
        let command: Command = match serde_json::from_slice(&line) {
            Ok(c) => c,
            Err(_) => break,
        };
        if command.validate().is_err() {
            break;
        }
        match command {
            Command::Stop => break,
            Command::Reset => {
                event(pipe, "restoring").await;
                host.cleanup().map_err(|_| "recovery_incomplete")?;
                active = false;
                event(pipe, "session_clean").await;
            }
            Command::Start(request) if !active => match host.start(request) {
                Ok(()) => {
                    active = true;
                    event(pipe, "route_ready").await;
                }
                Err(_) => {
                    host.cleanup().map_err(|_| "recovery_incomplete")?;
                    event(pipe, "session_clean").await;
                    event(pipe, "activation_failed").await;
                }
            },
            _ => break,
        }
    }
    event(pipe, "restoring").await;
    host.cleanup().map_err(|_| "recovery_incomplete")?;
    event(pipe, "restored").await;
    Ok(())
}

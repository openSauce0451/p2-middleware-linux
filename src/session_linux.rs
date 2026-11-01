// src/session_linux.rs
use std::{io, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Network {
    fn cleanup(&mut self) -> io::Result<()>;
    fn start(&mut self, request: Request) -> io::Result<()>;
    fn maintain(&mut self) {}
    fn failed(&self) -> bool;
}

#[derive(Clone, Debug)]
pub struct Request {
    pub settings: crate::config::Settings,
    pub interface: u32,
}

impl Request {
    pub fn validate(&self) -> io::Result<()> {
        // TODO: validate IP, subnet, interface
        Ok(())
    }
}

async fn event(pipe: &mut (impl AsyncWrite + Unpin), name: &str) {
    let _ = crate::control_linux::send(pipe, &serde_json::json!({"event":name})).await;
}

pub async fn run(
    pipe: &mut (impl AsyncRead + AsyncWrite + Unpin),
                 mut lines: crate::control_linux::Lines,
                 host: &mut impl Network,
) -> Result<(), &'static str> {
    // Copy this entire function verbatim from the real session.rs
    // It's platform-agnostic logic
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

        let line = match tokio::time::timeout(Duration::from_millis(100), lines.next(&mut pipe)).await {
            Err(_) => continue,
            Ok(Ok(Some(line))) => line,
            _ => break,
        };

        let command: crate::control_linux::Command = match serde_json::from_slice(&line) {
            Ok(c) => c,
            Err(_) => break,
        };

        if command.validate().is_err() {
            break;
        }

        match command {
            crate::control_linux::Command::Stop => break,
            crate::control_linux::Command::Reset => {
                event(pipe, "restoring").await;
                host.cleanup().map_err(|_| "recovery_incomplete")?;
                active = false;
                event(pipe, "session_clean").await;
            }
            crate::control_linux::Command::Start(request) if !active => {
                match host.start(request) {
                    Ok(()) => {
                        active = true;
                        event(pipe, "route_ready").await;
                    }
                    Err(_) => {
                        host.cleanup().map_err(|_| "recovery_incomplete")?;
                        event(pipe, "session_clean").await;
                        event(pipe, "activation_failed").await;
                    }
                }
            }
            _ => break,
        }
    }

    event(pipe, "restoring").await;
    host.cleanup().map_err(|_| "recovery_incomplete")?;
    event(pipe, "restored").await;
    Ok(())
}

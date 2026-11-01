//! Linux RouteClient: controls the elevated `p2-route` helper over a Unix socket.

use crate::{
    config::Settings,
    control_common::{send, Command as ControlCmd, Lines},
    control_linux, elevation_linux,
};
use std::{
    io,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub struct RouteClient {
    stop: Arc<AtomicBool>,
    state: Arc<AtomicU8>,
    commands: Sender<ControlCmd>,
    done: Receiver<bool>,
    pub events: Receiver<&'static str>,
}

impl RouteClient {
    pub fn session() -> io::Result<Self> {
        Self::spawn()
    }

    pub fn clean(&self) -> bool {
        self.state.load(Ordering::Acquire) == 1
    }

    pub fn active(&self) -> bool {
        self.state.load(Ordering::Acquire) == 2
    }

    pub fn apply(&mut self, settings: Settings, interface: u32) -> io::Result<()> {
        if !self.clean() {
            return Err(io::Error::other("gateway_not_ready"));
        }
        let request = ControlCmd::Start(crate::request::Request { settings, interface });
        request.validate()?;
        self.state.store(0, Ordering::Release);
        self.commands
        .send(request)
        .map_err(|_| io::Error::other("helper_disconnected"))
    }

    pub fn reset(&mut self) {
        self.state.store(0, Ordering::Release);
        let _ = self.commands.send(ControlCmd::Reset);
    }

    pub fn request_stop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }

    pub fn finished(&mut self) -> io::Result<Option<bool>> {
        match self.done.try_recv() {
            Ok(done) => Ok(Some(done)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(io::Error::other("helper_controller_ended")),
        }
    }

    fn spawn() -> io::Result<Self> {
        let parent = std::process::id();
        let socket_path = control_linux::socket_path(parent)?;
        let binary = std::env::current_exe()?.with_file_name("p2-route");

        let state = Arc::new(AtomicU8::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (commands, incoming) = mpsc::channel();
        let (tx_events, events) = mpsc::channel();
        let (tx_done, done) = mpsc::channel();

        let worker_state = state.clone();
        let worker_stop = stop.clone();

        thread::Builder::new()
        .name("p2-route-control".into())
        .spawn(move || {
            let success = control_loop(
                socket_path,
                parent,
                binary,
                worker_state,
                incoming,
                tx_events,
                worker_stop,
            )
            .unwrap_or(false);
            let _ = tx_done.send(success);
        })?;

        Ok(Self {
            stop,
            state,
            commands,
            done,
            events,
        })
    }
}

fn control_loop(
    socket_path: PathBuf,
    parent: u32,
    binary: PathBuf,
    state: Arc<AtomicU8>,
    incoming: Receiver<ControlCmd>,
    tx_events: Sender<&'static str>,
    stopped: Arc<AtomicBool>,
) -> io::Result<bool> {
    let runtime = control_linux::runtime()?;
    runtime.block_on(async {
        let path = socket_path
        .to_str()
        .ok_or_else(|| io::Error::other("socket_path"))?;

        // Bind before launching, so the helper cannot race ahead of the listener.
        let server = control_linux::server(path)?;

        let _ = tx_events.send("Approve the system prompt to start the network helper.");
        let mut child = elevation_linux::elevate(
            binary
            .to_str()
            .ok_or_else(|| io::Error::other("binary_path"))?,
                                                 path,
                                                 parent,
        )?;

        let mut stream = match tokio::time::timeout(Duration::from_secs(30), server.connect()).await
        {
            Ok(Ok(stream)) => stream,
                     Ok(Err(e)) => return Err(e),
                     Err(_) => {
                         return Err(io::Error::new(
                             io::ErrorKind::TimedOut,
                             "helper_connect_timeout",
                         ))
                     }
        };

        send(&mut stream, &ControlCmd::Session).await?;

        let mut lines = Lines::default();
        let mut stop_sent: Option<Instant> = None;

        loop {
            if stopped.load(Ordering::Acquire) && stop_sent.is_none() {
                // Keep reading recovery events after requesting stop.
                send(&mut stream, &ControlCmd::Stop).await?;
                stop_sent = Some(Instant::now());
            }
            if stop_sent.is_some_and(|t| t.elapsed() > Duration::from_secs(120)) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "helper_cleanup_timeout",
                ));
            }
            if stop_sent.is_none() {
                while let Ok(command) = incoming.try_recv() {
                    send(&mut stream, &command).await?;
                }
            }

            match tokio::time::timeout(Duration::from_millis(100), lines.next(&mut stream)).await {
                Ok(Ok(Some(line))) => {
                    if let Ok(text) = std::str::from_utf8(&line) {
                        if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
                            match value["event"].as_str() {
                                Some("session_clean") => state.store(1, Ordering::Release),
                     Some("route_ready") => state.store(2, Ordering::Release),
                     Some("restoring" | "recovery_incomplete") => {
                         state.store(0, Ordering::Release)
                     }
                     _ => {}
                            }
                        }
                        if let Some(message) = friendly(text) {
                            let _ = tx_events.send(message);
                        }
                    }
                }
                Ok(Ok(None)) | Ok(Err(_)) => {
                    // Socket closure can precede process exit by a few scheduler ticks.
                    for _ in 0..30 {
                        if let Some(status) = child.try_wait()? {
                            return Ok(status.success());
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    return Err(io::Error::other("helper_channel_closed"));
                }
                Err(_) => {
                    if let Some(status) = child.try_wait()? {
                        return Ok(status.success());
                    }
                }
            }
        }
    })
}

fn friendly(line: &str) -> Option<&'static str> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    Some(match value["event"].as_str()? {
        "session_clean" => "Network cleanup complete. Ready for a PS3 address.",
         "route_ready" => "Linux gateway is active. Set the PS3 gateway to this PC.",
         "restoring" => "Restoring the previous network settings...",
         "restored" => "Previous network settings restored.",
         "administrator_required" => "The network helper needs administrator permission.",
         "recovery_incomplete" => {
             "Cleanup could not finish. The saved record was kept; it is retried on next start."
         }
         "store_unavailable" => {
             "The protected cleanup record is unavailable. No network change was made."
         }
         "activation_failed" => "Gateway setup failed and was rolled back.",
         _ => return None,
    })
}

impl Drop for RouteClient {
    fn drop(&mut self) {
        // Worker requests cleanup; socket closure unblocks the helper if it stalls.
        self.stop.store(true, Ordering::Release);
    }
}

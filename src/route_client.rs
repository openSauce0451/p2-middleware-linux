//! Unprivileged GUI controller for a separately elevated, narrowly scoped helper.
use crate::{
    config::Settings,
    control::{self, Command, Lines},
    elevation,
    windows_host::Request,
};
use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub struct RouteClient {
    stop: Arc<AtomicBool>,
    state: Arc<AtomicU8>,
    commands: mpsc::Sender<Command>,
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
        let request = Command::Start(Request {
            settings,
            interface,
        });
        request.validate()?;
        self.state.store(0, Ordering::Release);
        self.commands
            .send(request)
            .map_err(|_| io::Error::other("helper_disconnected"))
    }
    pub fn reset(&mut self) {
        self.state.store(0, Ordering::Release);
        let _ = self.commands.send(Command::Reset);
    }

    fn spawn() -> io::Result<Self> {
        let request = Command::Session;
        let state = Arc::new(AtomicU8::new(0));
        let worker_state = state.clone();
        let (commands, incoming) = mpsc::channel();
        let path = std::env::current_exe()?.with_file_name("p2-route.exe");
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let (tx, events) = mpsc::channel();
        let (complete, done) = mpsc::channel();
        thread::Builder::new().name("p2-route-control".into()).spawn(move || {
            let result = (|| -> io::Result<bool> {
                let runtime = control::runtime()?;
                runtime.block_on(async {
                    let parent=std::process::id();
                    let name=control::pipe_name(parent);
                    let mut pipe=control::server(&name)?;
                    if stopped.load(Ordering::Acquire) { return Err(io::Error::other("cleanup_cancelled")); }
                    let _=tx.send("Approve Windows permission for the network helper.");
                    // ShellExecute may wait for UAC; this is a background worker, never the UI thread.
                    let process=elevation::launch(&path,&name,parent)?;
                    tokio::time::timeout(Duration::from_secs(30),pipe.connect()).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut,"helper_connect_timeout"))??;
                    control::verify_client(&pipe,process.id())?;
                    control::send(&mut pipe,&request).await?;
                    let mut lines=Lines::default();
                    let mut stop_sent=None;
                    loop {
                        if stopped.load(Ordering::Acquire) && stop_sent.is_none() {
                            // Keep reading recovery events after requesting stop.
                            control::send(&mut pipe,&serde_json::json!({"command":"Stop"})).await?;
                            stop_sent=Some(Instant::now());
                        }
                        if stop_sent.is_some_and(|t|t.elapsed()>Duration::from_secs(120)) {
                            return Err(io::Error::new(io::ErrorKind::TimedOut,"helper_cleanup_timeout"));
                        }
                        if stop_sent.is_none() {
                            while let Ok(command) = incoming.try_recv() {
                                control::send(&mut pipe, &command).await?;
                            }
                        }
                        match tokio::time::timeout(Duration::from_millis(100),lines.next(&mut pipe)).await {
                            Ok(Ok(Some(line))) => {
                                eprintln!("[route] {}", String::from_utf8_lossy(&line));
                                if let Ok(text)=std::str::from_utf8(&line) {
                                    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
                                        match value["event"].as_str() {
                                            Some("session_clean") => worker_state.store(1, Ordering::Release),
                                            Some("route_ready") => worker_state.store(2, Ordering::Release),
                                            Some("restoring" | "recovery_incomplete") => worker_state.store(0, Ordering::Release),
                                            _ => {}
                                        }
                                    }
                                    if let Some(message)=friendly(text) {let _=tx.send(message);}
                                }
                            }
                            Ok(Ok(None)) | Ok(Err(_)) => {
                                // Pipe closure can precede process exit by a few scheduler ticks.
                                for _ in 0..30 {
                                    if let Some(success)=process.finished()? {return Ok(success);}
                                    tokio::time::sleep(Duration::from_millis(100)).await;
                                }
                                return Err(io::Error::other("helper_channel_closed"));
                            }
                            Err(_) => {
                                if let Some(success)=process.finished()? {return Ok(success);}
                            }
                        }
                    }
                })
            })();
            let success=match result {
                Ok(success)=>success,
                Err(e)=>{
                    let _=tx.send(if e.raw_os_error()==Some(1223) {"Windows permission was cancelled. No network setup was started."} else {"Could not complete the network-helper session. If setup had begun, check recovery before changing the PS3 gateway."});
                    false
                }
            };
            let _=complete.send(success);
        })?;
        Ok(Self {
            stop,
            state,
            commands,
            done,
            events,
        })
    }
    pub fn request_stop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
    pub fn finished(&mut self) -> io::Result<Option<bool>> {
        match self.done.try_recv() {
            Ok(done) => Ok(Some(done)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => {
                Err(io::Error::other("helper_controller_ended"))
            }
        }
    }
}
impl Drop for RouteClient {
    fn drop(&mut self) {
        // Worker requests cleanup. GUI process exit closes the pipe even if this thread is gone.
        self.stop.store(true, Ordering::Release);
    }
}
fn friendly(line: &str) -> Option<&'static str> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    Some(match value["event"].as_str()? {
        "session_clean" => "Network cleanup complete. Ready for a PS3 address.",
        "route_ready" => "Windows gateway is active. Set the PS3 gateway to this PC.",
        "restoring" => "Restoring the previous Windows network settings...",
        "restored" => "Previous Windows network settings restored.",
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

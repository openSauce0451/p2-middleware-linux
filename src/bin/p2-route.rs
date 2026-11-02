use p2_middleware::{
    control::{self, Command, Lines},
    session,
};
use std::{io, process::ExitCode, time::Duration};

#[cfg(windows)]
use p2_middleware::native_gateway::NativeHost;
#[cfg(windows)]
use p2_middleware::windows_host::{elevated, JournalStore};
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeClient;

#[cfg(not(windows))]
use p2_middleware::{
    elevation_linux::elevated, journal_linux::JournalStore, network_linux::NativeHost,
};
#[cfg(not(windows))]
use tokio::net::UnixStream;

/// Control channel to the GUI: a named pipe on Windows, a Unix domain socket
/// elsewhere. Both satisfy `AsyncRead + AsyncWrite + Unpin`, which is why
/// `serve` below is written only once.
#[cfg(windows)]
type Channel = NamedPipeClient;
#[cfg(not(windows))]
type Channel = UnixStream;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 || args[0] != "--pipe" || args[2] != "--parent" {
        eprintln!("usage: p2-route --pipe <name> --parent <pid>");
        return ExitCode::FAILURE;
    }
    let parent: u32 = args[3].parse().unwrap_or(0);
    match run(&args[1], parent) {
        Ok(true) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

fn run(name: &str, parent: u32) -> io::Result<bool> {
    let runtime = control::runtime()?;
    runtime.block_on(async {
        // `control::client` is the platform transport: it validates the name
        // grammar and verifies the far end is the process that launched us.
        let mut stream = control::client(name, parent)?;
        let result = serve(&mut stream).await;
        if let Err(reason) = result {
            // A closed reporting channel must not abort recovery.
            let _ = control::send(&mut stream, &serde_json::json!({"event": reason})).await;
        }
        Ok(result.is_ok())
    })
}

async fn serve(stream: &mut Channel) -> Result<(), &'static str> {
    let mut lines = Lines::default();
    let line = tokio::time::timeout(Duration::from_secs(30), lines.next(stream))
    .await
    .map_err(|_| "request_timeout")?
    .map_err(|_| "invalid_request")?
    .ok_or("request_cancelled")?;

    let command: Command = serde_json::from_slice(&line).map_err(|_| "invalid_request")?;
    if !matches!(command, Command::Session) {
        return Err("invalid_request");
    }
    if !elevated() {
        return Err("administrator_required");
    }

    // `JournalStore` + `NativeHost` are the platform pair: the Linux
    // network/journalling modules, or the Windows IpHelper address aliases
    // plus the firewall-record journal. Both implement `session::Network`.
    let store = JournalStore::open().map_err(|_| "store_unavailable")?;
    let mut host = NativeHost::new(store);
    session::run(stream, lines, &mut host).await
}

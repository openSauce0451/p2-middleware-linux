//! Linux privileged network helper, invoked via `pkexec`.

use p2_middleware::{
    control::{self, Command, Lines},
    elevation_linux, journal_linux, network_linux, session,
};
use std::{io, process::ExitCode, time::Duration};
use tokio::net::UnixStream;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 4 || args[0] != "--pipe" || args[2] != "--parent" {
        eprintln!("usage: p2-route --pipe <socket> --parent <pid>");
        return ExitCode::FAILURE;
    }
    let parent: u32 = args[3].parse().unwrap_or(0);
    match run(&args[1], parent) {
        Ok(true) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

fn run(socket_path: &str, parent: u32) -> io::Result<bool> {
    let runtime = control::runtime()?;
    runtime.block_on(async {
        let mut stream = p2_middleware::control_linux::client(socket_path, parent)?;
        let result = serve(&mut stream).await;
        if let Err(reason) = result {
            // A closed reporting channel must not abort recovery.
            let _ = control::send(&mut stream, &serde_json::json!({"event": reason})).await;
        }
        Ok(result.is_ok())
    })
}

async fn serve(stream: &mut UnixStream) -> Result<(), &'static str> {
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
    if !elevation_linux::elevated() {
        return Err("administrator_required");
    }

    let store = journal_linux::JournalStore::open().map_err(|_| "store_unavailable")?;
    let mut host = network_linux::NativeHost::new(store);
    session::run(stream, lines, &mut host).await
}

use p2_bridge_core::{
    bad, channel,
    gateway::{self, event, Authorization},
    lobby_advertisement::AdvertisePlatform,
    lobby_diagnostics::{SearchDistance, SearchPlatform},
    udp_relay::{self, UdpRelayConfig},
};
use serde_json::json;
use std::{
    env,
    io::{self, BufRead, Read},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    thread,
    time::{Duration, Instant},
};
#[cfg(feature = "web-auth")]
use std::{
    io::{IsTerminal, Write},
    path::PathBuf,
};
use zeroize::Zeroizing;

fn serve(args: &[String]) -> io::Result<()> {
    let mut bind = "127.0.0.1:27017".parse::<SocketAddr>().unwrap();
    let mut peer = Ipv4Addr::LOCALHOST;
    let mut native_cm = false;
    let mut seconds = 600u64;
    let mut sessions = 3;
    let mut search_platform = SearchPlatform::default();
    let mut search_distance = SearchDistance::default();
    let mut advertise_platform = AdvertisePlatform::default();
    let mut udp_upstream: Option<SocketAddr> = None;
    let mut udp_ports: Option<Vec<u16>> = None;
    for pair in args.chunks(2) {
        if pair.len() != 2 {
            return Err(bad("missing_option_value"));
        }
        match pair[0].as_str() {
            "--bind" => bind = pair[1].parse().map_err(|_| bad("bind"))?,
            "--native-cm" => native_cm = pair[1].parse().map_err(|_| bad("native_cm"))?,
            "--peer" => peer = pair[1].parse().map_err(|_| bad("peer"))?,
            "--seconds" => seconds = pair[1].parse().map_err(|_| bad("seconds"))?,
            "--sessions" => sessions = pair[1].parse().map_err(|_| bad("sessions"))?,
            "--search-platform" => search_platform = SearchPlatform::parse(&pair[1])?,
            "--search-distance" => search_distance = SearchDistance::parse(&pair[1])?,
            "--advertise-platform" => advertise_platform = AdvertisePlatform::parse(&pair[1])?,
            "--udp-upstream" => {
                udp_upstream = Some(pair[1].parse().map_err(|_| bad("udp_upstream"))?)
            }
            "--udp-ports" => {
                let mut ports = Vec::new();
                for part in pair[1].split(',') {
                    let port = part.parse::<u16>().map_err(|_| bad("udp_ports"))?;
                    if port == 0 {
                        return Err(bad("udp_ports"));
                    }
                    if !ports.contains(&port) {
                        ports.push(port);
                    }
                    if ports.len() > 8 {
                        return Err(bad("udp_ports"));
                    }
                }
                udp_ports = Some(ports);
            }
            _ => return Err(bad("unknown_option")),
        }
    }
    let private = |ip: Ipv4Addr| ip.is_private() || ip.is_loopback();
    if !(matches!(bind.ip(), std::net::IpAddr::V4(ip) if private(ip))
        || (native_cm && bind == "0.0.0.0:27017".parse::<SocketAddr>().unwrap()))
        || (native_cm && (!peer.is_private() || bind.port() != 27017))
        || !private(peer)
        || seconds == 0
        || seconds > 86400
        || !(1..=1000).contains(&sessions)
        || udp_upstream.is_some_and(|u| {
            !u.is_ipv4()
            || u.ip().is_loopback()
            || u.ip().is_unspecified()
            || u.port() == 0
            || matches!(u.ip(),
                        std::net::IpAddr::V4(ip) if p2_bridge_core::legacy_cm::LEGACY_CM.contains(&ip))
        })
        {
            return Err(bad("configuration_bounds"));
        }
        // One bounded JSON line, delivered by a private local pipe/SSH, never a command argument.
        let mut line = Zeroizing::new(Vec::new());
        io::stdin()
        .lock()
        .take(16385)
        .read_until(b'\n', &mut line)?;
        if line.len() > 16384 || !line.ends_with(b"\n") {
            return Err(bad("authorization_input_limit"));
        }
        let auth: Authorization =
        serde_json::from_slice(&line).map_err(|_| bad("authorization_json"))?;
        drop(line);
        auth.validate()?;
        if native_cm
            && matches!(auth.cm.ip(), std::net::IpAddr::V4(ip) if p2_bridge_core::legacy_cm::LEGACY_CM.contains(&ip))
            {
                return Err(bad("upstream_overlaps_native_addresses"));
            }
            let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;

        // UDP relay: only meaningful with --native-cm, because the legacy
        // aliases exist only while the native gateway is active. Defaults:
        // ports [27017] on each legacy address; upstream is the modern CM the
        // authorization already carries, overridable with --udp-upstream.
        let mut udp = if native_cm {
            let config = UdpRelayConfig {
                peer,
                upstream: udp_upstream.unwrap_or(auth.cm),
                ports: udp_ports.unwrap_or_else(|| vec![27017]),
                seconds,
                max_flows: sessions,
            };
            Some(udp_relay::UdpRelay::spawn(config)?)
        } else {
            None
        };

        event(
            "listening",
            json!({"bind":bind.to_string(),"peer":peer.to_string(),"seconds":seconds,"sessions":sessions,"central_service":false,"search_platform":search_platform.name(),"search_distance":search_distance.name(),"advertise_platform":advertise_platform.name(),"udp_relay":native_cm}),
        );
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut count = 0;
        let mut rejected = 0;
        while Instant::now() < deadline && count < sessions && rejected < 32 {
            match listener.accept() {
                Ok((s, addr)) => {
                    if addr.ip() != std::net::IpAddr::V4(peer)
                        || (native_cm
                        && !p2_bridge_core::legacy_cm::accepts(s.local_addr()?, addr, peer))
                        {
                            rejected += 1;
                            drop(s);
                            continue;
                        }
                        count += 1;
                    event("ps3_connected", json!({"session":count}));
                    if let Err(e) = gateway::relay_with_lobby_policies(
                        s,
                        &auth,
                        deadline,
                        gateway::LobbyPolicies {
                            search_platform,
                            search_distance,
                            advertise_platform,
                        },
                    ) {
                        event(
                            "session_end",
                            json!({"reason":e.to_string(),"kind":format!("{:?}",e.kind())}),
                        );
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(e),
            }
        }
        if let Some(mut u) = udp.take() {
            u.stop();
        }
        event(
            "stopped",
            json!({"sessions":count,"rejected_peers":rejected}),
        );
        Ok(())
}
fn probe(address: SocketAddr) -> io::Result<()> {
    let (socket, _) = channel::connect(address, Instant::now() + Duration::from_secs(15))?;
    drop(socket);
    event(
        "official_handshake_pass",
        json!({"endpoint":address.to_string(),"result":1,"application_login_sent":false}),
    );
    Ok(())
}
fn probe_encrypted(address: SocketAddr) -> io::Result<()> {
    use p2_bridge_core::protocol as p;
    let deadline = Instant::now() + Duration::from_secs(20);
    let (mut socket, crypto) = channel::connect(address, deadline)?;
    let mut body = Vec::new();
    p::vi(1, p::MODERN_PROTOCOL, &mut body);
    channel::send_frame(
        &mut socket,
        &crypto.encode(&p::message(9805, &[], &body)),
                        deadline,
    )?;
    p::vi(7, 20, &mut body);
    p::bin(6, b"english", &mut body);
    let mut header = Vec::new();
    p::fixed64(1, 0x01a0_0000_0000_0000, &mut header);
    p::vi(2, 0, &mut header);
    channel::send_frame(
        &mut socket,
        &crypto.encode(&p::message(5514, &header, &body)),
                        deadline,
    )?;
    for _ in 0..16 {
        let frame = channel::read_frame(&mut socket, deadline)?;
        let plain = Zeroizing::new(crypto.decode(&frame)?);
        for message in p::flatten(&plain)? {
            if p::id(&message)? == 751 {
                let (_, h, b) = p::proto(&message)?;
                let result = p::uint(&p::fields(b)?, 1)?.unwrap_or(2);
                event(
                    "official_encrypted_probe",
                    json!({"anonymous":true,"eresult":result,"hmac_verified":true,"player_credentials_sent":false,"ps3_connected":false}),
                );
                channel::send_frame(
                    &mut socket,
                    &crypto.encode(&p::message(706, h, &[])),
                                    deadline,
                )?;
                return Ok(());
            }
        }
    }
    Err(bad("probe_no_logon_response"))
}
fn run() -> io::Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("serve") => serve(&args[1..]),
        Some("probe") if args.len() == 2 => probe(args[1].parse().map_err(|_| bad("endpoint"))?),
        Some("probe-encrypted") if args.len() == 2 => {
            probe_encrypted(args[1].parse().map_err(|_| bad("endpoint"))?)
        }
        #[cfg(feature = "web-auth")]
        Some("directory") if args.len() == 1 => {
            println!(
                "{}",
                json!(p2_bridge_core::auth::directory()?
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>())
            );
            Ok(())
        }
        #[cfg(feature = "web-auth")]
        Some("authorize") if args.len() == 4 && args[1] == "--qr" => {
            if io::stdout().is_terminal() {
                return Err(bad("authorization_requires_private_output_pipe"));
            }
            let cm = args[3].parse::<SocketAddr>().map_err(|_| bad("cm"))?;
            let auth = p2_bridge_core::auth::authorize(&PathBuf::from(&args[2]), cm)?;
            // stdout is ONLY the explicit credential pipe. Operational events go to stderr.
            let out = Zeroizing::new(serde_json::to_vec(&json!({"account_name":auth.account_name,"refresh_token":auth.refresh_token,"cm":auth.cm.to_string()})).map_err(|_| bad("auth_serialize"))?);
            io::stdout().lock().write_all(&out)?;
            io::stdout().lock().write_all(b"\n")?;
            Ok(())
        }
        _ => {
            eprintln!("portal2-gateway directory | probe <CM-IP:port> | authorize --qr <local.svg> <CM-IP:port> | serve [--bind private-IP:port --peer PS3-IP --seconds 600 --sessions 3 (max 86400 / 1000) --search-platform preserve|any --search-distance preserve|worldwide --advertise-platform preserve|default --udp-ports 27017 --udp-upstream <CM-IP:port>]\nAuthorize stdout contains credentials: connect it directly to serve stdin over a local pipe or SSH.");
            Err(bad("usage"))
        }
    }
}
fn main() {
    if let Err(e) = run() {
        event(
            "fatal",
            json!({"reason":e.to_string(),"kind":format!("{:?}",e.kind())}),
        );
        std::process::exit(1);
    }
}

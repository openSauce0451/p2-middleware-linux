use p2_bridge_core::{
    bad, channel,
    gateway::{self, event, Authorization},
    lobby_advertisement::AdvertisePlatform,
    lobby_diagnostics::{SearchDistance, SearchPlatform},
    udp_relay::{self, UdpRelayConfig},
};

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
            "--udp-upstream" => udp_upstream = Some(pair[1].parse().map_err(|_| bad("udp_upstream"))?),
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
    if !(matches!(bind.ip(),std::net::IpAddr::V4(ip) if private(ip))
        || (native_cm && bind == "0.0.0.0:27017".parse::<SocketAddr>().unwrap()))
        || (native_cm && (!peer.is_private() || bind.port() != 27017))
        || !private(peer)
        || seconds == 0
        || seconds > 86400
        || !(1..=1000).contains(&sessions)
        // New: a UDP upstream must be a usable IPv4 endpoint and must never
        // be one of the locally-owned legacy aliases, or the relay would
        // forward console datagrams straight back into its own listeners.
        || udp_upstream.is_some_and(|u| {
            !u.is_ipv4()
            || u.ip().is_loopback()
            || u.ip().is_unspecified()
            || u.port() == 0
            || matches!(u.ip(), std::net::IpAddr::V4(ip) if p2_bridge_core::legacy_cm::LEGACY_CM.contains(&ip))
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
            && matches!(auth.cm.ip(),std::net::IpAddr::V4(ip) if p2_bridge_core::legacy_cm::LEGACY_CM.contains(&ip))
            {
                return Err(bad("upstream_overlaps_native_addresses"));
            }
            let listener = TcpListener::bind(bind)?;
        listener.set_nonblocking(true)?;

        // UDP relay: only meaningful with --native-cm, because the legacy
        // aliases exist only while the native gateway is active. Defaults:
        // ports [27017] on each legacy address; upstream is the modern CM the
        // authorization already carries, overridable with --udp-upstream for
        // live-testing against a capture-derived endpoint.
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
            json!({"bind":bind.to_string(),"peer":peer.to_string(),"seconds":seconds,"sessions":sessions,"central_service":false,"search_platform":search_platform.name(),"search_distance":search_distance.name(),"advertise_platform":advertise_platform.name(),"udp_relay":native_cm,"udp_upstream":udp.as_ref().map(|u| u.flow_count())}),
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
        // Stops the relay threads and prints udp_relay_stopped before "stopped".
        if let Some(mut u) = udp.take() {
            u.stop();
        }
        event(
            "stopped",
            json!({"sessions":count,"rejected_peers":rejected}),
        );
        Ok(())
}

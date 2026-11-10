use crate::{
    bad,
    channel::{self, Envelope},
    lobby_advertisement::AdvertisePlatform,
    lobby_diagnostics::{SearchDistance, SearchPlatform},
    protocol as p,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    io,
    net::{Shutdown, SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

/// Deserialized from an SSH pipe or the local QR flow, never from command-line credentials.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub account_name: String,
    pub refresh_token: String,
    pub cm: SocketAddr,
}
impl Drop for Authorization {
    fn drop(&mut self) {
        self.account_name.zeroize();
        self.refresh_token.zeroize();
    }
}
impl Authorization {
    pub fn validate(&self) -> io::Result<()> {
        if self.account_name.is_empty()
            || self.account_name.len() > 128
            || self.refresh_token.len() < 32
            || self.refresh_token.len() > 8192
        {
            return Err(bad("authorization_shape"));
        }
        if self.cm.port() == 0
            || !self.cm.ip().is_ipv4()
            || self.cm.ip().is_loopback()
            || self.cm.ip().is_unspecified()
        {
            return Err(bad("cm_address"));
        }
        Ok(())
    }
}
// No raw payload, PSN ticket, account name, SteamID or token ever enters this logger.
pub fn event(name: &str, data: serde_json::Value) {
    eprintln!(
        "{}",
        json!({"unix_ms":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),"event":name,"data":data})
    );
}
pub fn translate_login(input: &[u8], account: &str, token: &str) -> io::Result<Vec<u8>> {
    let (id, h, b) = p::proto(input)?;
    if id != 5514 {
        return Err(bad("first_message_not_logon"));
    }
    let fields = p::fields(b)?;
    if p::bytes(&fields, 90)?.is_none_or(|v| v.is_empty())
        || p::bytes(&fields, 91)?.is_none_or(|v| v.is_empty())
    {
        return Err(bad("missing_psn_ticket_or_service"));
    }
    // Remove every credential/identity alternative, including duplicate fields.
    let mut body = p::without(
        b,
        &[
            1, 4, 7, 8, 22, 41, 42, 43, 50, 51, 52, 60, 80, 81, 83, 84, 85, 86, 87, 90, 91, 92, 93,
            94, 95, 101, 103, 105, 108,
        ],
    )?;
    p::vi(1, p::MODERN_PROTOCOL, &mut body);
    p::vi(7, 20, &mut body);
    p::vi(8, 1, &mut body);
    p::bin(50, account.as_bytes(), &mut body);
    p::bin(108, token.as_bytes(), &mut body);
    // Public/Individual/Desktop, account component zero until Steam authenticates.
    let message = p::message(id, h, &body);
    p::identity(&message, 0x0110_0001_0000_0000, 0)
}

#[derive(Default)]
struct Session {
    identity: Option<(u64, u32)>,
    downstream_messages: u64,
    upstream_messages: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LobbyPolicies {
    pub search_platform: SearchPlatform,
    pub search_distance: SearchDistance,
    pub advertise_platform: AdvertisePlatform,
}

pub fn relay(ps3: TcpStream, auth: &Authorization, deadline: Instant) -> io::Result<()> {
    relay_with_search_policy(ps3, auth, deadline, SearchPlatform::Preserve)
}
pub fn relay_with_search_policy(
    ps3: TcpStream,
    auth: &Authorization,
    deadline: Instant,
    search_platform: SearchPlatform,
) -> io::Result<()> {
    relay_with_search_policies(
        ps3,
        auth,
        deadline,
        search_platform,
        SearchDistance::Preserve,
    )
}
pub fn relay_with_search_policies(
    ps3: TcpStream,
    auth: &Authorization,
    deadline: Instant,
    search_platform: SearchPlatform,
    search_distance: SearchDistance,
) -> io::Result<()> {
    relay_with_lobby_policies(
        ps3,
        auth,
        deadline,
        LobbyPolicies {
            search_platform,
            search_distance,
            advertise_platform: AdvertisePlatform::Preserve,
        },
    )
}
pub fn relay_with_lobby_policies(
    ps3: TcpStream,
    auth: &Authorization,
    deadline: Instant,
    policies: LobbyPolicies,
) -> io::Result<()> {
    let (steam, upstream) = channel::connect(
        auth.cm,
        deadline.min(Instant::now() + Duration::from_secs(15)),
    )?;
    event(
        "official_channel_ready",
        json!({"rsa_oaep_sha1":true,"hmac_verified_on_receive":true}),
    );
    relay_connected(ps3, steam, upstream, auth, deadline, policies)
}
fn relay_connected(
    mut ps3: TcpStream,
    mut steam: TcpStream,
    upstream: Envelope,
    auth: &Authorization,
    deadline: Instant,
    policies: LobbyPolicies,
) -> io::Result<()> {
    let mut hello = Vec::new();
    p::vi(1, p::MODERN_PROTOCOL, &mut hello);
    channel::send_frame(
        &mut steam,
        &upstream.encode(&p::message(9805, &[], &hello)),
        deadline,
    )?;
    ps3.set_nodelay(true)?;
    channel::send_frame(
        &mut ps3,
        &p::old_message(1305, &1u32.to_le_bytes()),
        deadline,
    )?;
    let first = channel::read_frame(
        &mut ps3,
        deadline.min(Instant::now() + Duration::from_secs(20)),
    )?;
    let clear = Zeroizing::new(Envelope::legacy().decode(&first)?);
    let translated = Zeroizing::new(translate_login(
        &clear,
        &auth.account_name,
        &auth.refresh_token,
    )?);
    channel::send_frame(&mut steam, &upstream.encode(&translated), deadline)?;
    event(
        "login_translated",
        json!({"emsg":5514,"psn_fields_forwarded":false,"steam_token_downstream":false}),
    );
    drop(clear);
    drop(translated);
    let upstream = Arc::new(upstream);
    let shared = Arc::new(Mutex::new(Session::default()));
    let mut from_ps3 = ps3.try_clone()?;
    let mut to_steam = steam.try_clone()?;
    let closing_steam = steam.try_clone()?;
    let closing_ps3 = ps3.try_clone()?;
    let up = upstream.clone();
    let state = shared.clone();
    let sender = thread::spawn(move || {
        let result = (|| -> io::Result<()> {
            loop {
                let packet = channel::read_frame(&mut from_ps3, deadline)?;
                let plain = Zeroizing::new(Envelope::legacy().decode(&packet)?);
                for mut message in p::flatten(&plain)? {
                    let id = p::id(&message)?;
                    if id == 5514 || (1303..=1305).contains(&id) {
                        return Err(bad("unexpected_reauthentication"));
                    }
                    let identity = state
                        .lock()
                        .unwrap()
                        .identity
                        .ok_or_else(|| bad("client_message_before_authenticated"))?;
                    let (effective, audit) = crate::lobby_diagnostics::adapt_with_distance(
                        &message,
                        policies.search_platform,
                        policies.search_distance,
                    );
                    if let Some(audit) = audit {
                        event("lobby_search_policy", audit);
                    }
                    let (advertised, audit) =
                        crate::lobby_advertisement::adapt(&effective, policies.advertise_platform);
                    if let Some(audit) = audit {
                        event("lobby_advertisement_policy", audit);
                    }
                    let translated =
                        Zeroizing::new(p::identity(&advertised, identity.0, identity.1)?);
                    drop(advertised);
                    drop(effective);
                    if let Some(summary) = crate::lobby_advertisement::summarize(&message) {
                        event(
                            "lobby_publication_diagnostic",
                            json!({"direction":"client","summary":summary}),
                        );
                    }
                    if let Some(summary) = crate::lobby_diagnostics::summarize(&message) {
                        event(
                            "lobby_search_diagnostic",
                            json!({"direction":"client","summary":summary}),
                        );
                    }
                    // --- client_message hex tap (CLIENT direction) -------------------
                    if id == 5434 {
                        event("5434_hex_rev", json!({
                            "direction": "client",
                            "emsg": id,
                            "bytes": message.len(),
                                                             "payload_hex": crate::stun::hex(&message),
                        }));
                    }
                    // --- member-data hex tap (CLIENT direction) -------------------
                    if id == 6613 {
                        event("lobby_member_data_hex", json!({
                            "direction": "client",
                            "emsg": id,
                            "bytes": message.len(),
                                                             "payload_hex": crate::stun::hex(&message),
                        }));
                    }
                    message.zeroize();
                    channel::send_frame(&mut to_steam, &up.encode(&translated), deadline)?;
                    let mut state = state.lock().unwrap();
                    state.downstream_messages += 1;
                    event(
                        "client_message",
                        json!({"emsg":id,"bytes":translated.len()}),
                    );
                    if id == 706 {
                        return Ok(());
                    }
                }
            }
        })();
        let _ = closing_steam.shutdown(Shutdown::Both);
        let _ = closing_ps3.shutdown(Shutdown::Both);
        result
    });
    let received = (|| -> io::Result<()> {
        let mut login_deadline = deadline.min(Instant::now() + Duration::from_secs(30));
        loop {
            let packet = channel::read_frame(&mut steam, login_deadline)?;
            let plain = Zeroizing::new(upstream.decode(&packet)?);
            for mut message in p::flatten(&plain)? {
                let id = p::id(&message)?;
                if let Some(summary) = crate::lobby_diagnostics::summarize(&message) {
                    event(
                        "lobby_search_diagnostic",
                        json!({"direction":"server","summary":summary}),
                    );
                }
                if let Some(summary) = crate::lobby_advertisement::summarize(&message) {
                    event(
                        "lobby_publication_diagnostic",
                        json!({"direction":"server","summary":summary}),
                    );
                }
                // --- server_message hex tap (SERVER direction) -------------------
                if id == 5434 {
                    event("5434_hex_rev", json!({
                        "direction": "server",
                        "emsg": id,
                        "bytes": message.len(),
                                                "payload_hex": crate::stun::hex(&message),
                    }));
                }
                // --- member-data hex tap (SERVER direction) -------------------
                if id == 6612 || id == 6613 || id == 6614 {
                    event("lobby_member_data_hex", json!({
                        "direction": "server",
                        "emsg": id,
                        "bytes": message.len(),
                                                         "payload_hex": crate::stun::hex(&message),
                    }));
                }
                if id == 751 {
                    let (_, header, body) = p::proto(&message)?;
                    let hf = p::fields(header)?;
                    let bf = p::fields(body)?;
                    let result = p::uint(&bf, 1)?.unwrap_or(2);
                    event("official_login_result", json!({"eresult":result}));
                    if result == 1 {
                        let steamid =
                            p::uint(&hf, 1)?.ok_or_else(|| bad("login_missing_steamid"))?;
                        let session =
                            p::uint(&hf, 2)?.ok_or_else(|| bad("login_missing_session"))? as u32;
                        if steamid & 0xffff_ffff == 0
                            || steamid >> 56 != 1
                            || (steamid >> 52) & 15 != 1
                        {
                            return Err(bad("login_invalid_identity"));
                        }
                        let mut state = shared.lock().unwrap();
                        if state.identity.is_some() {
                            return Err(bad("duplicate_login_response"));
                        }
                        state.identity = Some((steamid, session));
                        login_deadline = deadline;
                    }
                    // Allow only legacy logon response fields. Tokens, URLs and account secrets
                    // from new extensions must not be copied into the zero-key PS3 channel.
                    let mut legacy = Vec::new();
                    for f in bf {
                        if [1, 2, 3, 4, 5, 6, 7, 10, 12, 20].contains(&f.number) {
                            legacy.extend(f.raw);
                        }
                    }
                    // Modern heartbeat field 3 also supplies the old out-of-game timer.
                    let lf = p::fields(&legacy)?;
                    if p::uint(&lf, 2)?.unwrap_or(0) == 0 {
                        if let Some(seconds) = p::uint(&lf, 3)? {
                            p::vi(2, seconds, &mut legacy);
                        }
                    }
                    let lf = p::fields(&legacy)?;
                    if p::uint(&lf, 4)?.unwrap_or(0) == 0 {
                        if let Some(ip) = p::bytes(&p::fields(body)?, 15)? {
                            if let Some(ipv4) = p::uint(&p::fields(ip)?, 1)? {
                                p::vi(4, ipv4, &mut legacy);
                            }
                        }
                    }
                    message = p::message(751, header, &legacy);
                }
                // Fresh login-key messages expose reusable credentials to the old channel.
                // This bridge uses the authorized refresh token and does not persist legacy keys.
                if [5463, 783].contains(&id) {
                    event("server_message_suppressed", json!({"emsg":id}));
                    message.zeroize();
                    continue;
                }
                if message.len() >= 8 && message[3] & 128 != 0 {
                    let (id, h, b) = p::proto(&message)?;
                    let mut legacy_header = Vec::new();
                    for f in p::fields(h)? {
                        if [1, 2, 3, 10, 11].contains(&f.number) {
                            legacy_header.extend(f.raw);
                        }
                    }
                    let cleaned = p::message(id, &legacy_header, b);
                    message.zeroize();
                    message = cleaned;
                }
                channel::send_frame(&mut ps3, &Envelope::legacy().encode(&message), deadline)?;
                shared.lock().unwrap().upstream_messages += 1;
                event("server_message", json!({"emsg":id,"bytes":message.len()}));
                message.zeroize();
            }
        }
    })();
    let _ = steam.shutdown(Shutdown::Both);
    let _ = ps3.shutdown(Shutdown::Both);
    let sent = sender.join().map_err(|_| bad("relay_thread"))?;
    let state = shared.lock().unwrap();
    event(
        "relay_summary",
        json!({"authenticated":state.identity.is_some(),"client_messages":state.downstream_messages,"server_messages":state.upstream_messages}),
    );
    received.and(sent)
}

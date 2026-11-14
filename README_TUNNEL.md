# p2-middleware-tunnel — PS3 Co-op Over the Internet (v0.2.0)

**Play Portal 2 co-op on your PS3 with a friend on their PS3 in another house — no port forwarding, no router wizardry.** Each of you runs a small program (the "middleware") on the PC sitting next to your console. The two programs find each other over the Internet and carry the game traffic between your PS3s, encrypted, as if the consoles were in the same room.

**New in v0.2.0:** the direct PS3-to-PS3 gameplay tunnel. Two consoles in different homes, on different networks, each behind its own PC — one Linux (with or without a VPN), one Windows — connect through the two middlewares. Validated end-to-end: a full co-op session between consoles hundreds of kilometers apart. Gameplay kicks may still occur during chapter transitions!

> Ready-made programs for **Linux and Windows 11** are on this repository's **Releases** page — no building, no compiling. The .zip archives includes three required files (`p2-middleware`, `p2-bridge` and `p2-route`); keep them in the same folder.

This README has two parts:

- **PART 1 — How to Run It:** step-by-step instructions. If you can copy-paste and click Next, you can do this.
- **PART 2 — Technical Reference:** architecture, wire formats, scripts, and internals, for developers and the curious.

---
---

## ⚠️ KNOWN BUGS:

- Local split-screen co-op progress gets reset when using the middleware online. **Make backups of your save files!** Workaround by playing in one continuous session
- Possible game kick at chapter transitions
- No Steam cloud save sync

---

# PART 1 — HOW TO RUN IT (Quick Start Guide)

## What you need

- Two players, each with: a PS3 with Portal 2, a PC on the **same home network** as the PS3, and the friend's contact.
- The middleware download for your PC's system (**Releases** page → latest → Linux .zip archive or Windows .zip archive).
- On each PC: the ability to run things as administrator (Windows) or know the `sudo` password (Linux).
- Steam account and the free Steam mobile app on your phone (used once to approve the PS3's Steam sign-in).
- Optional: a VPN service (set to **Moderate NAT / NAT 2** in its settings).

Do every step on **BOTH computers** before moving on to the next step.

---

## Step 1 — Download the program (both players)

1. Go to the repository's **Releases** page on GitHub.
2. Under the newest release, download the file for your PC's system:
   - **Windows users:** the `.zip` with the Windows program (three `.exe` files).
   - **Linux users:** the archive with the Linux files — it contains **`p2-middleware`**, **`p2-bridge`** and **`p2-route`**. They must sit in the same folder.
3. Extract it into its own folder (for example `p2-middleware` on the Desktop). Done — that's the whole installation.

---

## Step 2 — Give your PS3 a permanent address (both players, once)

So the setup never breaks when the PS3 restarts, tell your router to always hand your PS3 the same address. This is called a *DHCP reservation*: open your router's admin page (usually `http://192.168.0.1` or `http://10.0.0.1`), find your PS3 in the list of devices, and set it to "reserve" / "static". Any address is fine — note down which one it gets (it looks like `192.168.0.242` or `10.0.0.182`).

**Optionally**, set the IP address of your PS3 manually in the PS3 Network Settings -> IP Address Settings

---

## Step 3 — Point your PS3's router setting at your PC (both players, once)

This tells your PS3 to send its network traffic through your PC — which is what lets the middleware catch it.

On the PS3: **Settings → Network Settings → Internet Connection Settings → Custom**, and set:

| Setting | What to enter |
|---|---|
| IP Address | Manual — the reserved address from Step 2 (e.g. `192.168.0.242`) |
| **Default Router** | **Your PC's LAN address** (e.g. `192.168.0.33`) — *not* the actual router |
| DNS | Can remain the router (e.g. `192.168.0.1`) or `1.1.1.1` |
| Everything else | Defaults are fine |

⚠️ While your PS3 is set up this way, it needs the PC (and the middleware) running to reach the Internet. After a gaming session you can set the Default Router back to the real router to let the PS3 go online on its own again.

⚠️ Linux: if your PS3 can't connect to the Internet, you have to enable forwarding on your PC.

Run `sudo sysctl -w net.ipv4.ip_forward=1`

Additionally, if you are using a VPN app, run the following command with `<ps3-ip>` set as your private PS3 IP, and `<vpn-interface>` set as the interface name of the running VPN.

Run `sudo iptables -t nat -A POSTROUTING -s <ps3-ip> -o <vpn-interface> -j MASQUERADE`


---

## Step 4 — Connect your VPN, if you use one (optional)

Turn your VPN on before starting the middleware (Enable **Moderate NAT** or **NAT 2** in its settings — it's one checkbox). The workflow detects the tunnel automatically and applies a bypass so the PS3 and Steam traffic flow around it; without a tunnel it sets up the plain relay. Either way works.

---

## Step 5 — Collect your three numbers (both players)

Grab a pen or a chat window. You need:

1. **Your PS3's private IP address** — from Step 2 (e.g. `192.168.0.242`).
2. **Your PC's private (LAN / WiFi) IP address** — Windows: open a command prompt (`cmd`) and run `ipconfig`, look for *IPv4 Address*. Linux: `hostname -I`. This is the number your PS3's "Default Router" uses (Step 3).
3. **Your public IP address** — open `https://whatismyipaddress.com` in a browser and look for IPv4 address. **Important:** if you use a VPN, do this *while the VPN is connected* — that's the number your partner needs.

---

## Step 6 — Make the secret code (one player)

The two middlewares must prove they're really talking to each other. They share a **secret code** — a long random text only you two know.

One of you runs this (Linux/Mac terminal):

```bash
openssl rand -base64 32
```

(Or search the web for "random base64 32 bytes generator" and use that.)

Copy the result. It looks like:

```
KaWYu0nqnlY2vIWLcsqLD3qeWKJXVKPHsKal0KW3DnM=
```

Send it to your partner privately. Both of you will paste the **exact same code** into the settings.toml file in Step 8. (Roadmap feature: automated process with one 6-digit code via SPAKE2)

---

## Step 7 — Swap numbers with your partner

Tell each other:

- Your PS3's private IP address (Step 5, #1)
- Your public IP address (Step 5, #3)

You now each hold everything the settings file needs.

---

## Step 8 — Edit the settings.toml file (both players)

In your user folder there's a file called **`settings.toml`**. Open it with Notepad (Windows) or any text editor.

Linux: `~/.config/p2-middleware/settings.toml`

Windows: `\%LOCALAPPDATA%\P2middleware\settings.toml`

There's a worked example below, but the short version is: **your own numbers go on top, and the lines marked "partner" get the numbers your partner told you.**

**Template — check every line, yours will differ:**

```toml
ps3_ip     = "YOUR PS3 PRIVATE IP ADDRESS (Step 5 #1)"
pc_ip      = "YOUR PC PRIVATE ADDRESS (Step 5 #2)"
router_ip  = "YOUR HOME ROUTER, e.g. 192.168.0.1"
prefix_len = 24
crossplay  = true

[tunnel]
remote_ps3  = "YOUR PARTNER'S PS3 PRIVATE IP ADDRESS"
remote_port = 61795
wire_port   = 27050
wire_peer   = "YOUR PARTNER'S PUBLIC ADDRESS:27050"
key         = "THE SECRET CODE FROM STEP 6"
catch_all_port = 27051
port_band  = { first = 61700, last = 61800 }
```

**Worked example — a real working pair, so you see how the two files mirror each other:**

| Line | Player A (Linux) | Player B (Windows) |
|---|---|---|
| `ps3_ip` | `192.168.0.242` | `10.0.0.182` |
| `pc_ip` | `192.168.0.xxx` | `10.0.0.yyy` |
| `router_ip` | `192.168.0.1` | `10.0.0.1` |
| `remote_ps3` *(partner's)* | `10.0.0.182` | `192.168.0.242` |
| `wire_peer` *(partner's)* | `yyy.yyy.yyy.yyy:27050` | `xxx.xxx.xxx.xxx:27050` |
| `key` *(shared)* | same code | same code |

Everything not listed (`remote_port`, `wire_port`, `catch_all_port`, `port_band`) can stay exactly as in the template.

**Three rules that save headaches** (each one caused real failures before):

1. **Both `wire_port` values and both `wire_peer` ports must be `27050`.** Different numbers = total silence.
2. **Never add an `advertised_port` line**, no matter how tempting. The program discovers the right public port by itself - ONLY when you are behind **Strict NAT 3**, add an `advertised_port`, but even then the NAT-PMP feature was not fully proven to be working!
3. **The `key` must be character-for-character identical** on both sides — a single lost character breaks it quietly.

Save the file.

---

## Step 9 — Start the program (both players)

**On Linux** — open a terminal in the program's folder and run:

```bash
sudo ./p2-middleware --headless
```

The middleware launches in **headless mode**.

**On Windows** — right-click the program's icon and choose **Run as administrator**.

**First time signing into Steam from the PS3:** the terminal (or window) shows a **QR code** (on Linux it's drawn as blocky ASCII art right in the terminal). Open the **Steam mobile app** on your phone, tap the shield/Steam Guard icon → *Scan a QR code*, and point it at your screen. Approved — the PS3 is now signed into Steam through the middleware.

A stream of log lines follows — that's normal. You're watching for these good signs:

1. The Steam sign-in approving (above) and the bridge starting.
2. `tunnel_band_ready` — the console connection points are prepared.
3. `tunnel_keepalive_in` — **the two programs found each other over the Internet.** It repeats about every 8 seconds. This is the big one.

If you see `tunnel_peer_config_stale` instead, the program is literally telling you the fix: it prints the address it expected. Paste that into your `wire_peer` line (Step 8), restart the program.

---

## Step 10 — Optional: The two-minute sanity check (both players)

Before gaming, prove the road is open. One of you sends a nonsense message at the other's public IP address:

**Linux:**

```bash
echo "plug" | nc -u -w1 <PARTNER_PUBLIC_IP> 27050
```

Look at your **partner's** screen:

- ✅ It prints `tunnel_decrypt_rejected` — perfect. The message arrived but was gibberish (on purpose) — the road works.
- ❌ Nothing shows — your partner's inbound traffic is blocked. If they use a VPN, it must be set to Moderate NAT / NAT 2; otherwise their router needs UDP port 27050 forwarded. Fix this before playing — no game will connect otherwise.

---

## Step 11 — Play!

1. Launch **Portal 2** on both PS3s. (If you skipped it in Step 9, approve the Steam sign-in QR code on first launch.)
2. Start co-op: one of you creates and hosts the session, the other joins.
3. Connection events scroll by in the terminal as the session builds — `tunnel_out` and `tunnel_in` lines bouncing back and forth mean game traffic is flowing. Occasional `tunnel_source_alias_bound` lines are also normal.
4. The session survives the first minute → you're in. Enjoy Portal 2 co-op across the country.

---

## Step 12 — When you're done

Press **Ctrl-C** in the terminal (or close the Windows window). Everything tears itself down cleanly — routes, policy rules, SNAT, firewall rules, MSS clamps, and the `ip_forward` setting are all restored.

If you want your PS3 back online on its own afterwards, set its **Default Router** back to your real router (undo Step 3). The golden rule:

| PS3 Default Router | Program | Result |
|---|---|---|
| PC's LAN IP | running | ✅ co-op works |
| real router | closed | PS3 online normally, no co-op |
| PC's LAN IP | closed | ⚠️ PS3 has no Internet — start the program or undo Step 3 |
| real router | running | bridge up, but it sees no console traffic |

---

## Troubleshooting — symptom → what to do

| What you see | What it means | What to do |
|---|---|---|
| No `tunnel_keepalive_in` after a minute | Programs can't reach each other | Recheck `wire_peer` on both sides (Step 8 rule 1); run the Step 10 test; partner's UDP 27050 blocked? |
| `tunnel_peer_config_stale` | Wrong address typed in settings | Copy the hint the log prints into `wire_peer`, restart |
| `tunnel_alias_absent` | Program didn't get admin rights | Close it, run again as administrator / with `sudo` |
| Steam QR code never appears | Sign-in flow didn't start | Make sure the PS3's Default Router points at the PC (Step 3) and the program is running; retry from the PS3 |
| Co-op menu loads, then session dies during "checking connection" | One PC runs an old version | Re-download **both** PCs from the latest Release (dual-port tunnel needs v0.2.0+ on both sides) |
| Connects, then drops after ~4 minutes | Network mapping went stale | Keep the program running; check VPN stability |
| Log shows `tunnel_stun_rejected` code 430 | The game's session ticket expired | Restart the **game** on both PS3s (programs can stay running) |
| PS3 has no Internet at all | Program closed while PS3 still points at the PC | Either start the program, or restore the PS3's Default Router (Step 12's table) |

---

## Roadmap feature: no more secret code copy-paste

Steps 6–8 (making and sharing the secret code) are going away. **Automatic pairing** will let each of you just type a short human-friendly code — like pairing a TV to a streaming app ("482-913") — and the programs will securely build the secret themselves using a cryptographic handshake called **SPAKE2**.

---
---

# PART 2 — TECHNICAL REFERENCE

## What's new in v0.2.0

- **PS3↔PS3 gameplay tunnel** between two middleware instances (Linux host + Windows host), carrying console traffic directly peer-to-peer over one authenticated UDP channel — co-op between two homes with no third-party server in the gameplay data path.
- **Dual-port wire frames (Rev 6.1)** — the linchpin fix; see "Core mechanisms". Both sides must run v0.2.0+.
- **Verified NAT-PMP (Rev 8/9)** — port-forwarding discovery that verifies before advertising, originates MAP-UDP from the wire socket, and treats any configured pin as a seed rather than ground truth.
- **Authenticate-then-learn peer adoption (Rev 5) + endpoint announcements (Rev 7)** — the effective peer address follows NAT/VPN rewrites; stale configured endpoints are detected and named in the log with a copy-pasteable correction.
- Mixed-version interoperability: legacy single-port frames remain decodable; `P2_LEGACY_FRAMES=1` reverts *outbound* framing for staged rollouts.

## Topology

```
Console L 192.168.0.xxx ─ Linux PC ══ encrypted UDP tunnel (wire port 27050) ══ Windows PC ─ Console W 10.0.0.yyy
    (behind VPN / Moderate NAT)                                                   (raw ISP / home router NAT)
```

Each middleware holds a `/32` alias for the **remote** console's private IP, created by a privileged helper after `serve()` reports listening (bind loops retry in the background; `spawn()` never blocks). Console datagrams aimed at "the other console" land on alias sockets via routing / TPROXY (Linux) or raw-socket sniffing (Windows), get framed, sealed, and shipped to the peer's wire port. The PS3's Default Router points at its own PC (Part 1, Step 3), which is what funnels console traffic through the middleware.

## Core mechanisms

- **Dual-port data frames (Rev 6.1).** Data frames carry `[0x03][dst_port BE][src_port BE][payload]` inside the envelope: the receiving console's destination port *and* the sending console's source port. The receiver delivers to `local_ps3:dst_port` from an alias socket bound at `remote_ps3:src_port` — full 5-tuple reconstruction in both directions. Without the source port, replies leave from a tuple the console never dialed (e.g. a stale primary port), the game's connectivity check times out, and the session kicks — the defect behind test runs 42–45, isolated from a Wireshark train of identical 26-byte retransmitting probes with advancing counters. In the common case the required source-alias socket is already bound, since the consoles probe symmetric candidate sets; bind-on-demand covers the rest.
- **Port coverage.** Consoles sweep candidate ports from their LAN advertisement. Covered by: the primary `remote_port`, the optional `port_band` (capped at 512 sockets), and on-demand acquisition of anything else — Linux TPROXY catch-all, Windows sniffer with an ICMP shield hiding first-probe port-unreachables. Dynamic binds respect a 256-socket budget; undeliverable frames park in bounded queues (64/port, 5 s TTL) flushed by a janitor.
- **Crypto.** `channel::Envelope`: AES-256-CBC + HMAC-SHA1, 16-byte block padding, ≤1400-byte payloads. Session PSK arrives as base64 in `settings.toml` (rotatable session key, not an account credential).
- **Authenticate-then-learn.** Peer address adopted only from PSK-valid datagrams (`tunnel_peer_learned`); endpoint announcements ride every 4th keepalive (~32 s) as flag-2 `ip:port` frames.
- **NAT-PMP (Rev 8/9).** Route-derived per-session gateway discovery (LAN excluded; 10/8 prioritized; `a.b.255.254/.255` and `a.b.0.1` patterns probed), result code parsed u16 BE, 3600 s lifetime, internal-port echo verified, MAP-UDP from the wire socket (gateways bind mappings to request source ports), replies fished off the wire socket ahead of envelope decoding. With no truthful port (no pin, no grant), nothing is advertised and a plain keepalive goes out — the proven-safe black hole, never a fabricated endpoint.
- **STUN/TURN posture.** Probe-port responders answer Binding Requests with the advertised endpoint and TURN Allocate requests with dynamic relay allocations. Console→alias Binding Requests are **never** answered locally (a local answer credits a fake reflexive candidate — observed live); responses route back by txid from the probed tuple.

## The Linux workflow

One command does everything — validation, bypass bring-up, headless middleware launch, teardown on Ctrl-C:

```bash
sudo ./p2-middleware --headless
```

The workflow detects whether a VPN tunnel exists and applies the bypass accordingly; without a tunnel it sets up the plain relay. Headless mode prints the Steam Guard QR code as ASCII art in the terminal instead of opening a GUI window — scan it with the Steam mobile app (Steam Guard → Scan QR).

**Gateway/bypass state matrix** — the PS3's router setting and the bypass state must agree:

| PS3 Default Router | Bypass / middleware | Result |
|---|---|---|
| PC's LAN IP | up | ✅ co-op works |
| real router | down | PS3 online normally, no co-op |
| PC's LAN IP | down | PS3 has no Internet |
| real router | up | bridge up but sees no console traffic |

**Why forwarding matters:** `net.ipv4.ip_forward` must be `1` for any relay to work. The full workflow's network helper raises it as a side effect; standalone bypass runs set it on `up` and restore the prior value on `down`.

## Settings.toml reference

| Key | Section | Meaning |
|---|---|---|
| `ps3_ip` / `pc_ip` / `router_ip` / `prefix_len` | top | own-console / own-PC / home-router addresses, LAN prefix |
| `crossplay` | top | cross-play flag |
| `remote_ps3` | `[tunnel]` | other console's private IP (aliased locally) |
| `remote_port` | `[tunnel]` | other console's primary advertised port; fallback delivery socket |
| `wire_port` | `[tunnel]` | own Internet-facing wire bind (`27050`) |
| `wire_peer` | `[tunnel]` | peer's public endpoint — starting point, superseded by authenticate-then-learn (`yyy.yyy.yyy.yyy:27050`) |
| `key` | `[tunnel]` | base64 32-byte session PSK |
| `catch_all_port` | `[tunnel]` | TPROXY redirect target (Linux path) |
| `port_band.first/last` | `[tunnel]` | optional inclusive alias-port band |
| `advertised_port` | `[tunnel]` | **omit** — reserved for verified NAT-PMP seeding; a fabricated value is the classic black-hole misconfiguration |
| `stun_advertise` | `[tunnel]` | optional pinned STUN-advertised endpoint (freezes auto-detect) |

## Observable events (selected)

| Event | Meaning |
|---|---|
| `tunnel_wire_listening` / `tunnel_started` / `tunnel_band_ready` / `tunnel_band_partial` / `tunnel_alias_absent` | startup ladder |
| `tunnel_keepalive_in` / `_out` | wire liveness, 8 s cadence |
| `tunnel_peer_learned` / `tunnel_peer_public` / `tunnel_peer_config_stale` | peer identity management |
| `tunnel_in` / `tunnel_out` / `tunnel_in_first` | per-datagram counters; `src_port`/`dst_port` expose the reconstructed tuple |
| `tunnel_source_alias_bound` | Rev 6.1 receive-side source alias bind |
| `tunnel_dynamic_bound` / `tunnel_dynamic_exhausted` / `tunnel_port_busy` | on-demand binding health |
| `tunnel_nat_pmp_*` / `tunnel_public_detected` | NAT-PMP & public-IP lifecycle |
| `tunnel_check_forwarded_only` / `tunnel_stun_*` | gated STUN policy activity |
| `tunnel_stun_rejected` (code 430) | game credential expiry — restart the *game*, not the middleware |
| `tunnel_divert_gate_passed/failed` | TPROXY triplet verified install-*and*-fireable |

## Useful inspection commands

```bash
ss -tlnp | grep <Steam port>                          # bridge listening?
ip -4 addr show <lan-interface> | grep '/32'          # console aliases
ip rule show | grep 900                               # PS3 policy rule
sudo iptables -t nat -S POSTROUTING                   # SNAT rules
sysctl net.ipv4.ip_forward                            # relay prerequisite
```

## Debug output

The debugging purposes, enable P2_DEBUG_BRIDGE=1 and save logs into a log file. The following you can run as a one-shot-script.

```bash
#!/usr/bin/env bash
P2_DEBUG_BRIDGE=1 sudo -E ./p2-middleware --headless 2>&1 | tee ./p2test-linux.log
```

Enables `[bridge-raw]` JSON events from the bridge (unfiltered, unlike the friendly event names). For the tunnel, the per-datagram `tunnel_in`/`tunnel_out` events with their `src_port`/`dst_port` fields are the tuple-fidelity ground truth.

## Environment toggles

| Variable | Effect |
|---|---|
| `P2_LEGACY_FRAMES=1` | revert *outbound* wire frames to single-port Rev 6 form (interop/A-B with an unpatched peer; inbound always accepts both) |
| `P2_DEBUG_BRIDGE=1` | raw bridge JSON events |

## Building from source (developers only)

```bash
cargo build --release
```
For Windows build:

```bash
cargo build --release --target x86_64-pc-windows-gnu
```

Pure Rust, std threads only; crypto in `channel.rs`. End users: use the Release binaries — building is not part of the setup path.

## Repository layout / file map

| File | Purpose |
|---|---|
| `p2-middleware` | Main binary (requires `p2-bridge` alongside it) |
| `p2-bridge` | Bridge/gateway binary spawned by the middleware |
| `ps3_tunnel.rs` | wire threads, dual-port frames, alias table, NAT-PMP, STUN responders, announcements |
| `catch_all.rs` | Linux TPROXY divert server (`serve_until` → `handle_dynamic`) |
| `win_catch_all.rs` | Windows raw-socket sniffer + ICMP shield (`make_on_new_flow`) |
| `channel.rs` | `Envelope`: AES-256-CBC + HMAC-SHA1 sealing |
| `gateway.rs` | event/log sink (`event(name, json)`) |
| `udp_relay.rs` | legacy UDP relay + hooks (`bind_udp_reuse`) |
| `tunnel_setup.rs` | privileged helper: alias, fwmark, policy route, TPROXY rule; `divert_ready` install-vs-fireable gate |
| `config.rs` | `settings.toml` parsing |
| `stun.rs` | STUN classify/build/respond helpers |
| `main.rs` / wiring | startup ordering, component wiring |

## Known limitations

- The session key is exchanged manually until SPAKE2 pairing lands (below).
- At least one side's wire port (27050/UDP) must be reachable from the Internet — a VPN with Moderate NAT or a forwarded port satisfies this.
- `advertised_port` semantics: only a NAT-PMP-verified value is trustworthy; the verification gate intentionally refuses unverified pins.
- Threads blocked in `recv_from` terminate at process teardown if never woken (accepted design trade-off).
- The Linux binary requires `p2-bridge` in the same folder — the middleware spawns it.

## Roadmap: automatic pairing via code + SPAKE2

**Planned.** Replaces the manual base64 PSK exchange (Part 1, Steps 6–8) with a short human-readable pairing code fed into a SPAKE2 (Password-Authenticated Key Exchange) handshake over the wire. SPAKE2 derives a strong session key from a weak shared code while resisting offline dictionary and man-in-the-middle attacks; the key itself never crosses the wire. The derived key seeds the existing `Envelope` PSK slot unchanged — everything above it (Rev 6.1 frames, alias machinery, NAT-PMP, STUN posture) is untouched. Peer-learning already tolerates wrong preconfigured addresses, so only one side needs a reachable port.

## Acknowledgements

- **[iowngamesibought](https://github.com/iowngamesibought/p2-middleware)** — for the foundation work this project builds on: the upstream p2-middleware. The v0.2.0 PS3↔PS3 tunnel stands on that groundwork.
- **SecureSaucer33** — resilient, endlessly patient live-testing partner throughout the PS3↔PS3 tunnel feature development. Across dozens of test runs, late-night log captures, and packet dumps from two different networks, the tuple-fidelity defect behind the final fix was found and verified because someone kept showing up, re-running, and capturing one more time. Co-op was a two-person effort in every sense.

## Attribution

Built for private use connecting two consoles over the Internet. Sony, PlayStation, and PS3 are trademarks of Sony Interactive Entertainment; Valve and Steam are trademarks of Valve Corporation; Portal 2 is a trademark of Valve Corporation. This project is not affiliated with or endorsed by either.

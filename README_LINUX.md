# p2-middleware-linux

An AI-assisted Linux port of [p2-middleware](https://github.com/iowngamesibought/p2-middleware), extended with a **headless mode** and a **VPN bypass toolkit** so the full workflow works in one command while a VPN tunnel is active.

### **-> FOLLOW [Quick start](https://github.com/openSauce0451/p2-middleware-linux/blob/main/README_LINUX.md#quick-start) FOR RUNNING THE MIDDLEWARE ON LINUX.**

What this repo adds on top of the upstream middleware:

- `--headless` mode: prints the Steam Guard QR code as ASCII art to the terminal instead of requiring the GUI window

- A one-command orchestrator (`p2-coop-full.sh`) that wires up networking, NAT, and the bridge, then launches the middleware

- A VPN bypass script that routes PS3 and Steam CM traffic around the tunnel

**Credits:** this repository is a fork of [`iowngamesibought/p2-middleware`](https://github.com/iowngamesibought/p2-middleware). The bridge, channel, auth, and gateway logic in `p2-bridge` / `p2-bridge-core` is upstream's work; this fork contributes the Linux networking stack, the headless mode, and the orchestration scripts described below. Modifications to upstream sources are uncommitted local changes — see [Development notes](#development-notes).

## Background: why the bypass exists

The PC and PS3 share a LAN (`192.168.0.0/24`). The PC's default route points into a VPN tunnel (`e.g. tun0`), which breaks co-op in two distinct ways:

1. **PS3 traffic** follows the PC's default route into the tunnel, where the kill-switch drops it (it's not the PC's own traffic).

2. **Steam CM connections** complete the TCP handshake through the tunnel, then silently stall: VPN service forwards <Steam port> connections but does not carry the encrypted Steam frames that follow, producing `{"kind":"TimedOut","reason":"frame_deadline"}` from the bridge.

The bypass solves both with policy routing (problem 1) and explicit main-table routes to the LAN router for Steam CM networks (problem 2).

## Architecture

```
PS3 (192.168.0.242)      
 │  Default Router = PC (192.168.0.33)      
 ▼      
PC — eth0      
 ├─ ip rule: from 192.168.0.242 → table 900      
 │    └─ table 900: default via 192.168.0.1 dev eth0   	   (bypasses tunnel)      
 ├─ SNAT: 192.168.0.242 → 192.168.0.33                     (return traffic)      
 ├─ Legacy CM aliases on eth0 (~26 × /32)                	 (middleware adds)      
 └─ Main table routes for Steam CM /24s →    192.168.0.1   (bridge upstream)
```

The bridge listens on TCP <Steam port>; the PS3's Steam traffic is intercepted by the CM aliases and handled locally instead of leaving the LAN.

**Why the CM routes live in the main table:** table 900 is only consulted for packets *from* the PS3 (via `ip rule from ...`). The bridge's own upstream connection to Steam is locally generated and follows the **main** table — putting CM routes in table 900 has no effect on it.

**Why forwarding matters:** `net.ipv4.ip_forward` must be `1` for any relay to work. The middleware's network helper (`p2-route`) raises it as a side effect during the full workflow, but standalone bypass runs need the script to set it. The script enables it on `up` and restores the prior value on `down`.

## Repository layout

| File | Purpose |
| - | - |
| `p2-vpn-bypass.sh` | Networking: forwarding, CM routes, policy routing, SNAT, firewall, MSS clamp |
| `p2-coop-full.sh` | One-command orchestrator: validation → bypass up → middleware launch → teardown |
| `p2-middleware` | Main binary (requires `p2-bridge` alongside it) |
| `p2-bridge` | The bridge/gateway binary spawned by the middleware |


> **Note:** the middleware looks for the bridge next to its own executable. If you move or rebuild the middleware, keep `p2-bridge` in the same directory.

## Prerequisites

- Linux with `iptables-nft` (or legacy iptables), `iproute2`, and `sysctl`

- *Optional: VPN Linux client (tunnel interface; auto-detected — any `wg*` / `tun*` tunnel is also supported)

- A PS3 on the same subnet as the PC running the middleware, with **Portal 2 Steam-linked**

  - Steam co-op partner with a copy of Portal 2 can be **local or over Internet**

  - **PS3 <-> PS3 reportedly possible with each PS3 player running the middleware on their PC**

- The Steam mobile app on your phone, to scan the QR code

**Recommended:** set a DHCP reservation (static IP) for the PS3 on your router.

## Quick start

1. **Configure the PS3:** Settings → Network Settings → Internet Connection Settings → Custom. Set the **Default Router to the PC's LAN IP** (`192.168.0.33` in this setup). DNS can remain the router (e.g. `192.168.0.1`) or `1.1.1.1`. Set a manual IP address for your PS3 (`192.168.0.242` in this setup).

2. **Connect the VPN** on the PC (optional — the workflow detects the tunnel and applies the bypass accordingly; without a tunnel it still sets up the plain relay).

3. **Run the workflow:**
Set these according to your network:
<PS3_IP>	- e.g. 192.168.0.242
<Router_IP>	- e.g. 192.168.0.1
<PATH-p2-middleware> - e.g. ./p2-middleware

```
   sudo ./p2-coop-full.sh --ps3 <PS3_IP> --router <Router_IP> --bin <PATH-p2-middleware>
```

The script prints its configuration, clears stale state, brings up the bypass, and launches the middleware in headless mode.

1. **Approve Steam:** scan the ASCII QR code with the Steam mobile app and approve the login. Wait for:

```
   [headless] Steam approved — launch Portal 2 on the PS3.      
   [headless] Bridge is listening.
```

1. **Launch Portal 2 co-op on the PS3.** Connection events appear in the terminal as the session progresses.

2. **Stop with Ctrl-C.** The wrapper tears down the bypass: CM routes, policy rules, SNAT, firewall rules, MSS clamps, and restores `ip_forward`.

3. **Restore the PS3's Default Router to the real router** (`192.168.0.1`) if you want the PS3 online independently of the PC.

> **Gateway/bypass state matrix:** the PS3's router setting and the bypass state must agree. PS3→PC + bypass **up** = co-op works. PS3→router + bypass **down** = PS3 online, no co-op. Mismatched pairs give you either no Internet on the PS3 or a bridge that can't see its traffic.

### Running the pieces manually

Set PS3_IP, ROUTER_IP and IFACE (your PC network adapter) according to your network.

```
export PS3_IP=192.168.0.242 ROUTER_IP=192.168.0.1 IFACE=eth0      
      
sudo -E ./p2-vpn-bypass.sh up      # relay + CM bypass      
sudo ./p2-vpn-bypass.sh status     # inspect state      
sudo ./p2-vpn-bypass.sh down       # full teardown (works without env vars)      
      
./p2-middleware --headless \      
  --ps3 192.168.0.242 --router 192.168.0.1
```

> `sudo` strips the environment, so `up` needs either `sudo -E` with the variables exported, or `sudo env PS3_IP=... ROUTER_IP=... IFACE=... ./p2-vpn-bypass.sh up`. The wrapper passes them through with `sudo env` for this reason. `down` needs no variables — it recovers them from `/run/p2-vpn-bypass.state`.

## Troubleshooting

The most efficient diagnostic in this toolkit is the bridge's `probe` subcommand — it exercises the Steam upstream leg in isolation, with no PS3, bypass, or middleware in the loop:

```
./p2-bridge probe <Steam CM address>:<Steam port>      
# success: {"event":"official_handshake_pass", ...}      
# failure: {"kind":"TimedOut","reason":"frame_deadline","event":"fatal"}
```

### Command reference

| Symptom | Cause | Fix |
| - | - | - |
| PS3 has no Internet while pointed at the PC | `ip_forward=0`, or bypass down | `sudo -E ./p2-vpn-bypass.sh up`; check `sysctl net.ipv4.ip_forward` |
| Bridge `frame_deadline` with VPN on, works with VPN off | Steam CM traffic traversing the tunnel (port filtering) | Confirm CM routes: `sudo ./p2-vpn-bypass.sh status` should show `total: 8 / 8`; `ip route get <Steam CM IP>` must say `dev eth0`, not `dev tun0` |
| `probe` passes but full run still fails | Fault in the PS3/relay leg, not the tunnel | Run with `P2_DEBUG_BRIDGE=1` and read the raw bridge events between "connected" and "ended" |
| `RTNETLINK answers: File exists` | A stale rule/route from a prior run | Usually benign — the script flushes and re-adds idempotently; `down` then `up` if it persists |
| `ERROR: PS3 IP not set` | `sudo` stripped the environment | Use `sudo -E` with exports, or `sudo env PS3_IP=... ...` (the wrapper does this) |
| `The bridge executable is missing...` | `p2-bridge` not beside `p2-middleware` | `cp target/release/p2-bridge <middleware-dir>/`; the middleware resolves the bridge relative to its own executable |
| No adapter matches PS3 address | Adapter discovery returned empty (Linux port bug) | This fork's headless mode detects the LAN adapter by subnet; verify PS3 and PC share a /24 |
| Repeated SNAT rules accumulate | Stale rules from older script versions | Current `up`/`down` purge all SNAT rules for the PS3 before installing/removing; \`sudo iptables -t nat -S POSTROUTING  \|  grep \` to verify only one remains |


### Useful inspection commands

```
sudo ./p2-vpn-bypass.sh status          # everything the script tracks      
ss -tlnp | grep <Steam port>            # bridge listening?      
ip -4 addr show eth0 | grep '/32'       # legacy CM aliases (~26)      
ip rule show | grep 900                 # PS3 policy rule      
sudo iptables -t nat -S POSTROUTING     # SNAT rules      
sysctl net.ipv4.ip_forward              # relay prerequisite
```

### Debug output

```
sudo -E P2_DEBUG_BRIDGE=1 ./p2-coop-full.sh --ps3 <ip> --router <ip>
```

Enables `[bridge-raw]` JSON events from the bridge (unfiltered, unlike the friendly event names), which is how the Steam port filtering was isolated.

## Known limitations

- **The CM list is a snapshot.** The eight Steam CM /24s are networks observed in this environment. Valve rotates CM servers; if the directory returns an address outside these ranges, the bridge connection will route through the tunnel and `frame_deadline` returns. Mitigations:

- `DYNAMIC_CM=1 BRIDGE_BIN=./p2-bridge sudo -E ./p2-vpn-bypass.sh up` discovers the current CM list from the bridge (requires a build with the `web-auth` feature).

- Alternatively, a port-based mark (mangle `--dport <Steam port>` + `fwmark` rule) would route by port rather than address — more durable, but affects all host traffic to that port and is **not implemented or tested here**.

- **`--headless`still needs a display.** It uses `with_visible(false)`, which hides the window but does not remove eframe's windowing dependency. Over plain SSH it fails; use `xvfb-run` or run from a graphical session.

- **Approval ordering.** The Steam QR approval can complete before the gateway finishes configuring on slow discovery. Benign in practice; gating `approve()` on `self.confirmed` in `main.rs` would remove the race.

- **Single CM failure mode.** If Steam hands the middleware an IPv6 CM address, the IPv4-only filter in `auth.rs` prevents it from being used, so this is handled — but the directory query itself depends on `api.steampowered.com` being reachable.

- **Teardown sweep scope.** `down` unconditionally removes the eight known CM networks from the main table, regardless of who installed them. If you deliberately route Steam CM space elsewhere, `down` will remove that route.

## Development notes

This fork tracks [`iowngamesibought/p2-middleware`](https://github.com/iowngamesibought/p2-middleware) upstream. The `--headless` patch and debug instrumentation are **uncommitted local modifications** to upstream sources. To preserve them before pulling:

```
git remote add upstream https://github.com/iowngamesibought/p2-middleware.git   # if not already set      
git diff > p2-linux-headless.patch
```

Build:

```
cargo build --release      
# produces p2-middleware and p2-bridge in target/release/
```

Instrumentation added during debugging (kept because they're useful): `[bridge-raw]` event tee in `bridge.rs` (gated on `P2_DEBUG_BRIDGE`), and a `[channel]` dial log in `channel.rs`'s `connect()` showing peer address, family, and deadline budget.

### Upstream divergences worth reporting

Issues found in the upstream code during the Linux port, worked around here rather than fixed upstream:

- **`p2-bridge.exe`hardcoding.** Upstream resolves the bridge executable with a Windows-only filename on all platforms; a Linux build needs the `.exe` removed or `#[cfg]`-gated.

- **`network::adapters()`returns empty on Linux.** The adapter enumeration silently yields zero interfaces, so `for_console()` can never match; this fork's headless mode compensates with subnet-based detection.

- **`launch_error_message()`is Windows-only.** Error-code mapping and the "quarantined" wording are meaningless on Linux and obscure real `ENOENT`/`EACCES` failures.

### How the Steam port filtering was diagnosed

For the record, since it informs any future VPN work: the connection through the tunnel reached `ESTABLISHED` (per `ss -tnp`) yet produced no data — a handshake-complete/data-blackhole signature, not an MTU signature (the initial protocol frame is only 52–72 bytes). `p2-bridge probe` reproduced the failure with every other component removed, and adding a single main-table route for the CM's /24 to the LAN router flipped it to `official_handshake_pass`. MSS clamping was investigated extensively and found not to be implicated; the clamps remain in the script as defensive hardening for the 1420-byte tunnel MTU but are not load-bearing for this failure mode.


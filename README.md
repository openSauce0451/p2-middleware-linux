# ! INFO: This is a work-in-progress fork for Linux compatibility

# P2 middleware

A small Windows app that lets a stock PS3 copy of **Portal 2** sign in to Steam and
play co-op with a PC player again.

The PS3 game still tries to reach Steam's old login servers, which no longer
answer. P2 middleware runs on a Windows PC on the PS3's home network. It catches
only that login traffic from your PS3, signs in to the official Steam service with
a Steam account you approve, and relays the session. Everything else from the PS3,
such as PSN, DNS and game data, is passed through to your router unchanged.

> **Status: v0.1.0 preview.** PS3 to PC co-op works. So far it has only been
> confirmed with the PC partner on the same home network; play with a partner
> over the internet uses the same Steam services but has not been confirmed yet.
> PS3 to PS3 has not been tested. Please report results. See
> [Known limits](#known-limits).

This is an independent project. It is not affiliated with or endorsed by Valve,
Sony or Electronic Arts. It uses the official Steam services and your own accounts;
it is not a private server.

## What you need

| | Requirement |
| --- | --- |
| PC | Windows 11 x64 (Windows 10 is untested), administrator rights, wired or Wi-Fi connection to the home network |
| PS3 | Portal 2 on retail firmware. Tested with firmware 4.93, game update 1.04, BLUS30732 |
| Network | The PC running this app must be on the **PS3's home network and subnet**, for example both `192.168.1.x`, because it acts as the PS3's gateway. Your co-op partner does not need to be on this network |
| Steam account for the PS3 player | A Steam account that **owns Portal 2** and is **different from the one your co-op partner uses** |
| Phone | The Steam mobile app signed in to the PS3 player's Steam account, to scan the sign-in QR code |
| PC partner | Portal 2 on Steam, on this PC or any other. Tested on the `demo_viewer` beta branch (build 5270661); the default branch has not been tested |

To switch the PC copy to the tested branch: in the Steam library, right-click
**Portal 2 → Properties → Betas** and choose **demo_viewer**.

## Install

1. Download `p2-middleware-v0.1.0-windows-x64.zip` from the release page.
2. Extract it to a folder on a **local drive**, for example
   `C:\Users\<you>\Apps\p2-middleware`. Launching from a network share can hang
   before the window appears.
3. Keep all three programs together in that folder:
   - `p2-middleware.exe` is the app you open.
   - `p2-bridge.exe` relays the Steam session. It runs without administrator rights.
   - `p2-route.exe` is the network helper. It is the only part that asks for
     administrator permission.

Windows SmartScreen may warn because the files are not code-signed. Choose
**More info → Run anyway** only if you downloaded the zip from the official
release page and its SHA-256 matches `SHA256SUMS.txt`:

```powershell
Get-FileHash .\p2-middleware-v0.1.0-windows-x64.zip -Algorithm SHA256
```

## Setup guide

### 1. Find the PS3's IP address

On the PS3: **Settings → Network Settings → Settings and Connection Status List**.
Note the **IP Address** (for example `192.168.1.50`) and the **Default Router**
(your router, for example `192.168.1.1`).

The PS3 address must not change during play. If your router hands out addresses
automatically, either reserve this address for the PS3 in the router's DHCP
settings, or set it manually in step 5.

### 2. Start the app

Open `p2-middleware.exe`. Windows asks once whether to let the network helper make
changes; choose **Yes**. On every start, the helper first removes any network
changes this app left behind.

The window shows three status lights:

| Light | Green | Amber | Red / grey |
| --- | --- | --- | --- |
| **Network helper** | Ready | Starting or cleaning up | Stopped: press **Retry** |
| **Steam** | Signed in | Waiting for your approval | Sign-in failed / signed out |
| **Gateway** | Active | Connecting | Failed / off |

### 3. Sign in to Steam for the PS3 player

Under **Steam account**, press **Sign in**. A QR code appears. In the Steam mobile
app for the **PS3 player's** account, open **Steam Guard → Scan QR code** and
approve **Portal 2 local gateway**. The Steam light turns green and shows the
account name.

You never type a password into this app. The approval is kept in memory only and
is discarded when you press **Forget** or close the app.

### 4. Confirm the PS3

Enter the PS3's IP address under **PS3 IP address** and press **Confirm**. The app
finds the matching network adapter on the PC by itself. If the PC is on two
networks that both match, pick the home network from the list.

When the Gateway light turns green, the large **PS3 gateway** address appears.
This is the PC's own address on the home network, for example `192.168.1.20`.

### 5. Point the PS3 at the PC

On the PS3: **Settings → Network Settings → Internet Connection Settings →
Custom**, then choose your connection type (wired or wireless) and enter:

| Setting | Value |
| --- | --- |
| IP Address Setting | **Manual** |
| IP Address | The PS3 address from step 1 |
| Subnet Mask | Usually `255.255.255.0` |
| Default Router | **The PS3 gateway address shown in the app** |
| Primary DNS | Your router's address from step 1 |
| Secondary DNS | Leave empty or `0.0.0.0` |
| MTU | Automatic |
| Proxy Server | Do Not Use |
| UPnP | Enable |

Save, then run **Test Connection**. It should obtain an IP address and connect to
the internet.

Only change the PS3 gateway **after** the Gateway light is green. While it is not,
the PC does not forward the PS3's traffic.

### 6. Play co-op

1. Start Portal 2 on the PS3 and go online. The game's Steam login goes through
   the app to the account you approved in step 3.
2. Start Portal 2 on the PC with the PC player's own Steam account.
3. Make the two Steam accounts **friends on Steam** if they are not already.
4. On the PS3, open co-op and **invite the PC player's account from the PS3 game
   menu** (Steam friends). Accept the invite on the PC.

Use invites to play with someone specific. **Find Partner** is random public
matchmaking: your PS3 can be matched with any PC player searching at that moment,
not necessarily your PC.

### 7. When you are done

1. Set the PS3 back to its normal settings: **Internet Connection Settings →
   Easy**, or Custom with **Default Router** set to your router again.
2. Close the app with the window's close button. It waits until the network
   helper has removed its changes and then exits.

Do not shut down or sleep the PC while the gateway is active. If that happens
anyway, the leftover changes are removed the next time you open the app.

## What the app changes on Windows

Only while the gateway is active, and only on the selected network adapter:

- **26 temporary addresses.** The fixed old Steam login server addresses the PS3
  game tries to reach are added to the PC (`/32`, never used for the PC's own
  outgoing traffic). They expire after 12 minutes unless the app keeps renewing
  them, so they cannot linger long after a crash.
- **One firewall rule.** It allows only the PS3's address to reach `p2-bridge.exe`
  on TCP port 27017 at those addresses.
- **IPv4 forwarding on the adapter**, so the PC passes all other PS3 traffic to
  your router. If forwarding was already on, it is left on.

Before changing anything, the helper writes a record in
`C:\ProgramData\P2Middleware`. That folder is protected so only administrators and
SYSTEM can change it. The record is used to undo exactly these changes on stop,
close or the next start. The app does not change DNS, default routes, DHCP or any
other firewall rule. The PC's own Steam client and games are not affected.

The app saves only the PS3 address and detected network settings, in
`%LOCALAPPDATA%\P2Middleware\settings.toml`. No passwords, tokens or tickets are
written to disk.

## Security notes

- The PS3 game's login connection uses the original, weak PS3 channel encryption.
  This part runs only between the PS3 and the PC on your home network; keep it on
  a network you trust. The PC to Steam connection uses Steam's normal encryption.
- The Steam approval stays in the app's memory and is not saved. The bridge never
  sends your Steam token to the PS3.
- Only the PS3 address you confirm can use the bridge.

## Troubleshooting

| Problem | What to try |
| --- | --- |
| Network helper stays red | Press **Retry** and approve the Windows prompt. The app needs administrator permission for the helper. |
| Gateway turns red after Confirm | Check that the PS3 and the PC are on the same subnet and that the PC's address and router have not changed. Press **Confirm** again. |
| PS3 Test Connection fails | Check that **Default Router** on the PS3 is exactly the address the app shows, and that the Gateway light is green. |
| PS3 cannot sign in to Steam | Make sure the Steam light is green before starting the game, that the PS3 player's Steam account owns Portal 2, and that it is not your co-op partner's account. |
| Matched with strangers instead of your partner | Use a Steam friend invite from the PS3 game menu instead of Find Partner. |
| Windows asks whether to allow `p2-bridge.exe` | Allow it. The app's own firewall rule normally makes this unnecessary. |
| The window does not appear | Run the app from a local drive, not a network share. |

## Known limits

Tested: PS3 to PC co-op with the PC partner on the same home network (the app and
the partner's game on one PC), Windows 11, PC on the `demo_viewer`
branch, one PS3 at a time.

Not yet tested:
- PS3 to PS3 co-op
- A co-op partner on another network over the internet (expected to work, not yet
  confirmed)
- Windows 10
- PCs whose adapter gets its address from DHCP (testing used a fixed PC address)
- The PC Portal 2 default branch
- Long sessions, map transitions, reconnects
- Recovery after a forced crash or reboot while the gateway is active

Only one PS3 per PC is supported.

## Build from source

Requirements: Rust 1.99.1 (pinned by `rust-toolchain.toml`) and the Visual Studio
C++ build tools, on Windows x64.

```powershell
cargo build --workspace --release --locked
python scripts/package.py --build-dir target/release
```

`package.py` writes the release zip and its SHA-256 to `dist/`.

## License

MIT for this project; see `LICENSE`. The Steam encryption code adapted from
SteamKit in `crates/bridge-core` stays under LGPL-2.1-or-later. See
`SOURCE_NOTICES.md`.

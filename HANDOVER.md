# Shunkan (瞬間) — Handover & Implementation Document

**Date:** 2026-09-06  
**Repository:** `Ephraim-9/shunkan`  
**Current Branch:** `main` (commit `9f00618`)

---

## 1. Executive Summary & Current Status

In this session, we accomplished the following milestones:
1. **GitHub PR Resolution:** Successfully resolved, sequenced, and merged the full stack of 6 open pull requests (`#2` through `#7`) into `main`.
2. **Build & CI Hardening:**
   - Fixed UniFFI Kotlin compiler collision: renamed `ShunkanError::message` to `reason` (UniFFI Kotlin generates classes inheriting from `java.lang.Throwable`, where `message` is a reserved final property).
   - Fixed GitHub Actions Android NDK cache corruption and automated NDK discovery (`nttld/setup-ndk` local-cache disabled).
   - Successfully generated clean CI-built Android debug APK (`shunkan-debug-apk`).
3. **Local Dev & Persistent Desktop Toolchain:**
   - Relocated cargo target directory from full root partition (`/`) to `/media/helliot/DATA1/cargo-target/shunkan/target` via symlink.
   - Built a persistent local GTK-3 development environment under `/media/helliot/DATA1/gtk-env` so desktop builds succeed reliably without root disk exhaustion.
4. **P2P Discovery & QUIC Transport Fixes:**
   - **IPv4 Preference in mDNS:** Fixed `DiscoveredPeer::socket_addr()` to filter and prioritize IPv4 addresses (`10.162.219.x`) over link-local IPv6 addresses (`fe80::`), which were failing on `0.0.0.0:0`-bound QUIC client sockets.
   - **Pairing Dial Tie-break Bypass:** Fixed `run_mdns_discovery` in `desktop-linux/src-tauri/src/lib.rs` so the desktop actively dials discovered peers whenever a pairing PIN is armed, bypassing the passive tie-break wait.
5. **End-to-End Pairing Verified:**
   - Linux Desktop (`T590`, peer `peer-fd81f6a7132cbe50`) and Android (`SM-A075F`, peer `peer-1b587588a9825e81`) completed mutual TLS handshake and SPAKE2 PIN verification (`991905`).
   - Both devices pinned each other's BLAKE3 certificate fingerprints into their persistent trust stores (`paired_peers.json`).
6. **Sync Verification:**
   - **Android ➔ Desktop:** **CONFIRMED WORKING.** Sharing text from Android via "Share to Shunkan" was received, decoded, and recorded on the desktop over QUIC.
   - **Desktop ➔ Android:** **NOT WORKING YET.**
   - **Android UX Friction:** Using the Android system Share sheet works but is perceived as too cumbersome for daily clipboard sync.

---

## 2. Technical Architecture & Verified Flow

```
┌──────────────────────────────────────┐             QUIC (UDP 4433)             ┌─────────────────────────────────────┐
│            Linux Desktop             │◄───────────────────────────────────────►│            Android Phone            │
│                (T590)                │             Mutual TLS 1.3              │             (SM-A075F)              │
│       peer-fd81f6a7132cbe50          │          Pinned Fingerprints            │        peer-1b587588a9825e81        │
├──────────────────────────────────────┤                                         ├─────────────────────────────────────┤
│ • mDNS browse / advertise (4433)     │                                         │ • mDNS browse / advertise (4433)    │
│ • TrustStore: paired_peers.json      │                                         │ • TrustStore: paired_peers.json     │
│ • Wayland wlroots / X11 monitor      │                                         │ • Foreground SyncService (QUIC)     │
│ • Framed postcard control streams    │                                         │ • ShareTargetActivity (Share sheet) │
└──────────────────────────────────────┘                                         └─────────────────────────────────────┘
```

### Protocol Details
- **Discovery:** mDNS-SD on `_shunkan-sync._udp.local.` (port 4433).
- **Handshake:** QUIC connection using `rustls` with pinned BLAKE3 self-signed DER certificate fingerprints.
- **Pairing:** Single-use SPAKE2 exchange with Ed25519 group and channel binding over mutual TLS certificate fingerprints.
- **Data Wire Format:** Framed length-prefixed `postcard`-serialized binary messages (`Message::Handshake`, `Message::PairingHello`, `Message::PairingConfirm`, `Message::Clipboard`).

---

## 3. Root-Cause Analysis for Identified Issues

### A. Why Desktop ➔ Android Did Not Work
1. **Android Side Has No Auto-Write to System Clipboard:**
   - In `core/src/ffi.rs`, when the Android engine receives a `Message::Clipboard`, it records it to local history and calls `listener.on_clipboard_received(text, source)`.
   - In `mobile-android/app/src/main/java/com/shunkan/sync/EngineHolder.kt`, `Fanout` delegates to registered listeners.
   - In `MainActivity.kt`, `onClipboardReceived` is **not implemented**.
   - In `SyncService.kt`, there is no clipboard listener attached that writes received text to Android's `ClipboardManager`.
2. **Android 10+ (API 29+) Background Clipboard Write Restrictions:**
   - Even if `ClipboardManager.setPrimaryClip()` were called in `SyncService`, Android blocks background services from modifying the system clipboard unless:
     - The app is currently in the foreground (active window).
     - The app is the default Input Method Editor (IME / virtual keyboard).
     - The app has an active Accessibility Service with clipboard capabilities.
3. **Desktop Wayland Capture on COSMIC Desktop:**
   - Desktop runs under COSMIC (Wayland).
   - `shunkan-desktop` uses `arboard` with polling fallback. On Wayland, `arboard` cannot poll global clipboard content unless the Wayland window is focused, or an XWayland client copied the text, or a Wayland protocol extension like `ext-data-control-v1` / `wlr-data-control` (e.g. `wl-clipboard-rs`) is actively capturing clipboard events.

### B. Why Android ➔ Desktop Share Sheet is "Too Much Work"
- Currently, Android text must be selected -> Share -> Shunkan -> Send.
- While secure and privacy-respecting (no background sniffing), it requires 3–4 taps per sync operation.
- Users expect automatic or 1-tap clipboard sharing.

---

## 4. Work Completed & Commits on `main`

| Commit | Description |
|---|---|
| `e745a84` | `fix(core): rename ShunkanError::message to reason to avoid UniFFI Throwable conflict` |
| `6035057` | `ci(android): fix NDK setup and discovery in build-android script` |
| `9f00618` | `fix(p2p): prefer IPv4 in discovery socket_addr and dial peer during pairing` |

---

## 5. Next Session Roadmap & Implementation Plan

### Priority 1: Fix Desktop ➔ Android Sync
1. **Desktop Wayland Capture:**
   - Integrate `wl-clipboard-rs` or use `wl-paste -w` watcher when running in Wayland sessions (wlroots / COSMIC / Sway) to reliably detect copies without window focus.
2. **Android Incoming Clipboard Handling:**
   - In `EngineHolder.kt` or `SyncService.kt`, implement an incoming clipboard notification handler.
   - When text arrives from desktop:
     - Post a high-priority system notification: *"Clipboard received: [preview text]"* with a 1-tap action: **"Copy to Clipboard"** (clicking copies to `ClipboardManager` and dismisses notification).
     - Automatically update in-app history in `MainActivity.kt`.

### Priority 2: Improve Android ➔ Desktop UX ("Less Work")
1. **Quick Settings Tile (`ShunkanTileService`):**
   - Wire up the existing `ShunkanTileService.kt` to read the system clipboard when clicked (since tapping a tile briefly transitions the app to active context) and immediately broadcast it to desktop peers.
2. **Accessibility Service (Optional Power-User Mode):**
   - Provide an optional Accessibility Service toggle in settings that detects copy events in any app and syncs automatically without the Share menu.
3. **Clipboard Paste Notification / Floating Bubble:**
   - Optional floating bubble or persistent tile for 1-tap capture.

---

## 6. Local Setup Quick Reference

### Running the Desktop App
```bash
# Run headless or with GUI (auto-reconnects to paired Android phone):
cd /home/helliot/repos/shunkan
RUSTFLAGS="-L /media/helliot/DATA1/gtk-env/lib" \
PKG_CONFIG_PATH="/media/helliot/DATA1/gtk-env/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:/usr/share/pkgconfig" \
./target/debug/shunkan-desktop
```

### Trust Store Verification
- Desktop store: `~/.local/share/shunkan/paired_peers.json`
- Phone store: `/data/data/com.shunkan.sync/files/paired_peers.json`
- Confirmed paired device: `SM-A075F` (`peer-1b587588a9825e81`)

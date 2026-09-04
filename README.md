# Shunkan 瞬間

**Local-first, peer-to-peer clipboard and file synchronization between Linux and Android.**
No cloud, no account, no relay server — devices find each other on the local network and talk
directly over QUIC.

> **Status:** Discovery, transport, protocol, history and hashing are implemented and covered by
> 67 unit tests plus 8 integration tests. PIN-pairing verification works; the X25519 key exchange
> is still a scaffold. The Android client is Gradle scaffolding only — no sources yet, UniFFI
> bindings unwired. Not packaged for end users.

## Why

Every cross-device clipboard tool either routes your clipboard through someone else's server or
assumes you're inside one vendor's ecosystem. Shunkan does neither: discovery is mDNS, transport
is QUIC with self-signed TLS, and nothing leaves the local network.

## Architecture

```
core/                  shunkan-core — shared Rust engine
  discovery.rs         mDNS-SD broadcast + browse (_shunkan-sync._udp.local.)
  transport.rs         QUIC transport (quinn) with self-signed rustls certificates
  protocol.rs          wire protocol message types
  crypto.rs            BLAKE3 PIN-pairing verification (X25519 exchange scaffolded)
  history.rs           in-memory LRU clipboard history, BLAKE3-deduplicated
  hashing.rs           BLAKE3 chunk hasher for file integrity

desktop-linux/         Tauri v2 client (Rust backend + web frontend)
mobile-android/        Jetpack Compose client (scaffolded)
```

One engine, two frontends. The desktop and mobile clients are thin — all networking,
cryptography, and protocol handling live in `shunkan-core`, exposed to Android via UniFFI.

## Design invariants

These are enforced in review, not aspirations:

| | |
|---|---|
| **INV-01** | ~15 MB idle RAM, 20 MB hard ceiling |
| **INV-02** | Zero cloud reliance — local network only |
| **INV-03** | No polling loops on Android threads |
| **INV-04** | UniFFI for all FFI bindings |
| **INV-05** | BLAKE3 only for file chunks (SHA-256 prohibited) |

Defaults: QUIC on port `4433`, 64 KiB file chunks.

## Build

Requires a recent stable Rust toolchain.

```bash
cargo build --workspace          # core + desktop backend
cargo test  -p shunkan-core      # engine tests, including integration
```

The Linux desktop client additionally needs the [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/):

```bash
cd desktop-linux && cargo tauri dev
```

## Roadmap

- [ ] Wire UniFFI bindings and complete the Android client
- [ ] Replace the X25519 scaffold with a real key exchange
- [ ] Pairing UX (PIN verification is implemented; no UI yet)
- [ ] Chunked file transfer resume
- [ ] Packaging: AppImage / Flatpak for Linux

## License

Not yet licensed for reuse — see [issues](https://github.com/Ephraim-9/shunkan/issues) if you
want to use it.

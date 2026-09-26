# Shunkan 瞬間

**Local-first, peer-to-peer clipboard and file synchronization between Linux and Android.**
No cloud, no account, no relay server — devices find each other on the local network and talk
directly over QUIC.

> **Status:** 222 tests (203 unit, 19 async/integration). Discovery, QUIC transport, protocol,
> history, hashing, file-chunk reassembly and SPAKE2 PIN pairing are implemented. The Android client
> (IME, quick-settings tile, share target) runs on the Rust core through UniFFI. Not packaged for
> end users.

## Why

Every cross-device clipboard tool either routes your clipboard through someone else's server or
assumes you're inside one vendor's ecosystem. Shunkan does neither: discovery is mDNS, transport
is QUIC with self-signed TLS, and nothing leaves the local network.

## Architecture

```
core/                  shunkan-core — shared Rust engine
  discovery.rs         mDNS-SD broadcast + browse (_shunkan-sync._udp.local.)
  transport.rs         QUIC transport (quinn) over rustls
  protocol.rs          wire protocol message types
  identity.rs          persistent device identity: peer ID + self-signed TLS certificate
  pairing.rs           SPAKE2 PIN pairing, bound to both devices' TLS certificate fingerprints
  trust.rs             paired-device trust store + pinned-fingerprint TLS verifier
  crypto.rs            pairing PIN type and QUIC/TLS config tying identity to the trust store
  transfer.rs          file-chunk reassembly by index (tracks missing chunks)
  history.rs           in-memory LRU clipboard history, BLAKE3-deduplicated
  hashing.rs           BLAKE3 chunk hasher for file integrity
  ffi.rs               UniFFI exports for Android

desktop-linux/         Tauri v2 client (Rust backend + web frontend)
mobile-android/        Kotlin client: sync service, IME, quick-settings tile, share target
```

One engine, two frontends. The clients are thin — networking, cryptography and protocol handling
live in `shunkan-core`; Android calls it through UniFFI bindings.

There is no certificate authority: a peer is trusted only if its certificate's BLAKE3 fingerprint
was recorded in the trust store during PIN pairing.

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
cargo test  --workspace          # all tests, including integration
```

The Linux desktop client additionally needs the [Tauri v2 prerequisites](https://v2.tauri.app/start/prerequisites/):

```bash
cd desktop-linux && cargo tauri dev
```

## Roadmap

- [ ] Pairing UI on desktop (PIN pairing works in the core; the desktop reads the PIN from an environment variable)
- [ ] Chunked file transfer resume (reassembly tracks missing chunks; no resume request yet)
- [ ] Packaging: AppImage / Flatpak for Linux

## License

Not yet licensed for reuse — see [issues](https://github.com/Ephraim-9/shunkan/issues) if you
want to use it.

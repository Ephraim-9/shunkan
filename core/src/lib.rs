//! # Shunkan Core
//!
//! P2P clipboard sync and file sharing engine for Project Shunkan (瞬間).
//!
//! This crate provides the shared networking, cryptography, and protocol
//! handling layer used by both the Linux desktop (Tauri v2) and Android
//! (Jetpack Compose via UniFFI) frontends.
//!
//! ## Modules
//!
//! - [`discovery`] — mDNS-SD service broadcasting and discovery
//! - [`transport`] — QUIC transport with self-signed TLS certificates
//! - [`protocol`] — Wire protocol message types
//! - [`crypto`] — X25519 key exchange scaffold and PIN verification
//! - [`history`] — In-memory LRU clipboard history with BLAKE3 dedup
//! - [`hashing`] — BLAKE3 chunk hasher for file integrity
//!
//! ## Invariants
//!
//! - **INV-01**: Target ~15MB idle RAM, hard ceiling 20MB
//! - **INV-02**: Zero cloud reliance — all local network only
//! - **INV-03**: No polling loops on Android threads
//! - **INV-04**: Use UniFFI for FFI bindings
//! - **INV-05**: BLAKE3 only for file chunks (SHA-256 PROHIBITED)

pub mod crypto;
pub mod discovery;
pub mod hashing;
pub mod history;
pub mod protocol;
pub mod transport;

/// Default QUIC port for Shunkan P2P connections (per ADR-001).
pub const DEFAULT_PORT: u16 = 4433;

/// mDNS service type for local network discovery (per INV-02).
pub const SERVICE_TYPE: &str = "_shunkan-sync._udp.local.";

/// Default chunk size for file transfers (64 KiB).
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum clipboard history entries kept in memory (LRU).
pub const MAX_HISTORY_ENTRIES: usize = 100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_PORT, 4433);
        assert_eq!(SERVICE_TYPE, "_shunkan-sync._udp.local.");
        assert_eq!(DEFAULT_CHUNK_SIZE, 65536);
        assert_eq!(MAX_HISTORY_ENTRIES, 100);
    }
}

//! Paired-device trust store and the pinned-fingerprint TLS verifier.
//!
//! Shunkan has no certificate authority and no web PKI. A peer is trusted iff
//! the BLAKE3 fingerprint of the certificate it presents was recorded in this
//! store at pairing time. That is the whole trust model, and it is what
//! [`PinnedFingerprintVerifier`] enforces during the TLS handshake.
//!
//! ## Pairing mode
//!
//! An empty store can never grow if unknown peers are always rejected, so the
//! store carries an explicit *pairing mode* flag. While pairing mode is on, an
//! unknown certificate is accepted and its fingerprint is recorded
//! (trust-on-first-use). While it is off — the default — an unknown
//! fingerprint aborts the handshake.
//!
//! Pairing mode is deliberately a visible, switchable piece of state rather
//! than an implicit "accept anything" default: the PIN exchange that gates it
//! is added in a later change, and until then enabling it is the operator's
//! explicit decision.

use crate::identity::fingerprint_of;
use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as TlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Filename of the persisted trust store.
pub const PAIRED_PEERS_FILE: &str = "paired_peers.json";

/// A device this peer has paired with.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairedPeer {
    /// The peer's stable identifier.
    pub peer_id: String,
    /// Human-readable device name, as advertised at pairing time.
    pub device_name: String,
    /// Platform identifier (`linux`, `android`, …).
    pub platform: String,
    /// BLAKE3 fingerprint of the peer's certificate. This is the pinned value.
    pub fingerprint: String,
    /// When the pairing was recorded (seconds since UNIX epoch).
    pub paired_at: u64,
}

impl PairedPeer {
    /// Record a new pairing, stamped with the current time.
    pub fn new(
        peer_id: impl Into<String>,
        device_name: impl Into<String>,
        platform: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            device_name: device_name.into(),
            platform: platform.into(),
            fingerprint: fingerprint.into(),
            paired_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TrustFile {
    peers: Vec<PairedPeer>,
}

#[derive(Debug, Default)]
struct TrustState {
    /// peer_id -> pairing record.
    by_peer_id: HashMap<String, PairedPeer>,
    /// fingerprint -> peer_id, for handshake-time lookups.
    by_fingerprint: HashMap<String, String>,
    pairing_mode: bool,
}

impl TrustState {
    fn insert(&mut self, peer: PairedPeer) {
        // Re-pairing replaces the old record, including any stale fingerprint.
        if let Some(previous) = self.by_peer_id.insert(peer.peer_id.clone(), peer.clone()) {
            self.by_fingerprint.remove(&previous.fingerprint);
        }
        self.by_fingerprint.insert(peer.fingerprint, peer.peer_id);
    }

    fn remove(&mut self, peer_id: &str) -> Option<PairedPeer> {
        let removed = self.by_peer_id.remove(peer_id)?;
        self.by_fingerprint.remove(&removed.fingerprint);
        Some(removed)
    }
}

/// The set of devices this peer trusts, optionally backed by a file on disk.
#[derive(Debug)]
pub struct TrustStore {
    state: Mutex<TrustState>,
    path: Option<PathBuf>,
}

impl TrustStore {
    /// Create an empty, non-persistent trust store. Useful in tests.
    pub fn in_memory() -> Self {
        Self {
            state: Mutex::new(TrustState::default()),
            path: None,
        }
    }

    /// Load the trust store from `dir`, or create an empty one if absent.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        let path = dir.join(PAIRED_PEERS_FILE);
        let mut state = TrustState::default();

        if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            let file: TrustFile = serde_json::from_str(&raw)
                .with_context(|| format!("Failed to parse {}", path.display()))?;
            for peer in file.peers {
                state.insert(peer);
            }
            log::info!(
                "Loaded {} paired peer(s) from {}",
                state.by_peer_id.len(),
                path.display()
            );
        }

        Ok(Self {
            state: Mutex::new(state),
            path: Some(path),
        })
    }

    /// Turn trust-on-first-use on or off.
    pub fn set_pairing_mode(&self, enabled: bool) {
        let mut state = self.lock();
        state.pairing_mode = enabled;
        if enabled {
            log::warn!(
                "Pairing mode ENABLED — unknown devices on this network will be trusted on first \
                 connection until it is turned off"
            );
        } else {
            log::info!("Pairing mode disabled — only paired devices are accepted");
        }
    }

    /// Whether trust-on-first-use is currently enabled.
    pub fn pairing_mode(&self) -> bool {
        self.lock().pairing_mode
    }

    /// Record a pairing and persist the store.
    pub fn pair(&self, peer: PairedPeer) -> Result<()> {
        log::info!(
            "Pairing with {} ({}) — pinning fingerprint {}…",
            peer.device_name,
            peer.peer_id,
            &peer.fingerprint[..peer.fingerprint.len().min(16)]
        );
        self.lock().insert(peer);
        self.save()
    }

    /// Forget a pairing and persist the store. Returns the removed record.
    pub fn forget(&self, peer_id: &str) -> Result<Option<PairedPeer>> {
        let removed = self.lock().remove(peer_id);
        if removed.is_some() {
            self.save()?;
        }
        Ok(removed)
    }

    /// Whether this fingerprint belongs to a paired device.
    pub fn is_trusted_fingerprint(&self, fingerprint: &str) -> bool {
        self.lock().by_fingerprint.contains_key(fingerprint)
    }

    /// Look up a pairing record by certificate fingerprint.
    pub fn peer_by_fingerprint(&self, fingerprint: &str) -> Option<PairedPeer> {
        let state = self.lock();
        let peer_id = state.by_fingerprint.get(fingerprint)?;
        state.by_peer_id.get(peer_id).cloned()
    }

    /// Look up a pairing record by peer ID.
    pub fn peer(&self, peer_id: &str) -> Option<PairedPeer> {
        self.lock().by_peer_id.get(peer_id).cloned()
    }

    /// All paired devices.
    pub fn paired_peers(&self) -> Vec<PairedPeer> {
        self.lock().by_peer_id.values().cloned().collect()
    }

    /// Number of paired devices.
    pub fn len(&self) -> usize {
        self.lock().by_peer_id.len()
    }

    /// Whether no devices are paired.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Write the store to disk. A no-op for in-memory stores.
    pub fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };

        let file = TrustFile {
            peers: self.paired_peers(),
        };
        let json =
            serde_json::to_string_pretty(&file).context("Failed to serialize trust store")?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        std::fs::write(path, json)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        restrict_file_permissions(path)?;
        Ok(())
    }

    /// Decide whether a certificate should be accepted, recording it if this is
    /// a trust-on-first-use pairing.
    ///
    /// Returns the fingerprint on success so the caller can bind the connection
    /// to a known peer.
    fn authorize_certificate(&self, cert: &CertificateDer<'_>) -> Result<String, TlsError> {
        let fingerprint = fingerprint_of(cert);

        {
            let state = self.lock();
            if state.by_fingerprint.contains_key(&fingerprint) {
                return Ok(fingerprint);
            }
            if !state.pairing_mode {
                log::warn!(
                    "Rejecting peer with unpinned certificate fingerprint {}… (pairing mode is off)",
                    &fingerprint[..16]
                );
                return Err(TlsError::General(format!(
                    "unpaired device: certificate fingerprint {}… is not in the trust store",
                    &fingerprint[..16]
                )));
            }
        }

        // Pairing mode: trust on first use. The peer ID and device name are not
        // known at TLS time, so record a provisional entry keyed by fingerprint;
        // the handshake message that follows upgrades it with real metadata.
        let provisional = PairedPeer::new(
            format!("unknown-{}", &fingerprint[..16]),
            "unknown",
            "unknown",
            fingerprint.clone(),
        );
        log::warn!(
            "Trust-on-first-use: pinning previously unseen fingerprint {}…",
            &fingerprint[..16]
        );
        self.lock().insert(provisional);
        if let Err(e) = self.save() {
            log::error!("Failed to persist trust-on-first-use pairing: {}", e);
        }
        Ok(fingerprint)
    }

    /// Replace the provisional record created during trust-on-first-use with
    /// the real peer metadata carried by the handshake.
    pub fn promote_provisional(
        &self,
        fingerprint: &str,
        peer_id: &str,
        device_name: &str,
        platform: &str,
    ) -> Result<()> {
        let existing = self.peer_by_fingerprint(fingerprint);
        let Some(existing) = existing else {
            return Ok(());
        };
        if existing.peer_id == peer_id && existing.platform == platform {
            return Ok(());
        }

        let mut state = self.lock();
        state.remove(&existing.peer_id);
        state.insert(PairedPeer {
            peer_id: peer_id.to_string(),
            device_name: device_name.to_string(),
            platform: platform.to_string(),
            fingerprint: fingerprint.to_string(),
            paired_at: existing.paired_at,
        });
        drop(state);
        self.save()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TrustState> {
        // A poisoned trust store still holds valid data; recovering is strictly
        // better than aborting every future connection.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(unix)]
fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set 0600 permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// A [`ServerCertVerifier`] that accepts a peer iff its certificate fingerprint
/// is pinned in the [`TrustStore`].
///
/// Certificate chains, expiry, and hostnames are all irrelevant here: the
/// certificate *is* the identity, and the fingerprint is the only thing that
/// decides. Signature verification still runs normally, so a peer must actually
/// hold the private key for the certificate it presents.
#[derive(Debug)]
pub struct PinnedFingerprintVerifier {
    trust: Arc<TrustStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedFingerprintVerifier {
    /// Build a verifier backed by the given trust store.
    pub fn new(trust: Arc<TrustStore>) -> Self {
        Self {
            trust,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.trust.authorize_certificate(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("shunkan-trust-test-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_empty_store_trusts_nobody() {
        let store = TrustStore::in_memory();
        assert!(store.is_empty());
        assert!(!store.is_trusted_fingerprint("deadbeef"));
        assert!(!store.pairing_mode());
    }

    #[test]
    fn test_pair_and_lookup() {
        let store = TrustStore::in_memory();
        store
            .pair(PairedPeer::new("peer-1", "Phone", "android", "fp-1"))
            .unwrap();

        assert_eq!(store.len(), 1);
        assert!(store.is_trusted_fingerprint("fp-1"));
        assert_eq!(store.peer("peer-1").unwrap().device_name, "Phone");
        assert_eq!(store.peer_by_fingerprint("fp-1").unwrap().peer_id, "peer-1");
    }

    #[test]
    fn test_repairing_replaces_old_fingerprint() {
        let store = TrustStore::in_memory();
        store
            .pair(PairedPeer::new("peer-1", "Phone", "android", "fp-old"))
            .unwrap();
        store
            .pair(PairedPeer::new("peer-1", "Phone", "android", "fp-new"))
            .unwrap();

        assert_eq!(store.len(), 1);
        assert!(!store.is_trusted_fingerprint("fp-old"));
        assert!(store.is_trusted_fingerprint("fp-new"));
    }

    #[test]
    fn test_forget_removes_both_indexes() {
        let store = TrustStore::in_memory();
        store
            .pair(PairedPeer::new("peer-1", "Phone", "android", "fp-1"))
            .unwrap();

        let removed = store.forget("peer-1").unwrap().unwrap();
        assert_eq!(removed.peer_id, "peer-1");
        assert!(store.is_empty());
        assert!(!store.is_trusted_fingerprint("fp-1"));
        assert!(store.forget("peer-1").unwrap().is_none());
    }

    #[test]
    fn test_store_round_trips_through_disk() {
        let dir = temp_dir("roundtrip");
        {
            let store = TrustStore::load_or_create(&dir).unwrap();
            store
                .pair(PairedPeer::new("peer-1", "ThinkPad", "linux", "fp-1"))
                .unwrap();
        }

        let reloaded = TrustStore::load_or_create(&dir).unwrap();
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.is_trusted_fingerprint("fp-1"));
        assert_eq!(reloaded.peer("peer-1").unwrap().device_name, "ThinkPad");
        // Pairing mode is never persisted — it must be re-enabled deliberately.
        assert!(!reloaded.pairing_mode());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_unknown_certificate_rejected_when_not_pairing() {
        let identity = DeviceIdentity::generate().unwrap();
        let store = TrustStore::in_memory();

        let result = store.authorize_certificate(identity.cert_der());
        assert!(result.is_err(), "unpaired cert must be rejected");
        assert!(store.is_empty());
    }

    #[test]
    fn test_unknown_certificate_pinned_in_pairing_mode() {
        let identity = DeviceIdentity::generate().unwrap();
        let store = TrustStore::in_memory();
        store.set_pairing_mode(true);

        let fp = store.authorize_certificate(identity.cert_der()).unwrap();
        assert_eq!(fp, identity.fingerprint());
        assert!(store.is_trusted_fingerprint(identity.fingerprint()));

        // Once pinned, it is accepted even after pairing mode is turned off.
        store.set_pairing_mode(false);
        assert!(store.authorize_certificate(identity.cert_der()).is_ok());
    }

    #[test]
    fn test_pinned_certificate_accepted_without_pairing_mode() {
        let identity = DeviceIdentity::generate().unwrap();
        let store = TrustStore::in_memory();
        store
            .pair(PairedPeer::new(
                identity.peer_id().0.clone(),
                "Peer",
                "linux",
                identity.fingerprint(),
            ))
            .unwrap();

        assert!(store.authorize_certificate(identity.cert_der()).is_ok());
    }

    #[test]
    fn test_promote_provisional_replaces_placeholder_metadata() {
        let identity = DeviceIdentity::generate().unwrap();
        let store = TrustStore::in_memory();
        store.set_pairing_mode(true);
        store.authorize_certificate(identity.cert_der()).unwrap();

        let provisional = store.peer_by_fingerprint(identity.fingerprint()).unwrap();
        assert_eq!(provisional.platform, "unknown");

        store
            .promote_provisional(identity.fingerprint(), "peer-real", "ThinkPad X1", "linux")
            .unwrap();

        assert_eq!(store.len(), 1);
        let promoted = store.peer_by_fingerprint(identity.fingerprint()).unwrap();
        assert_eq!(promoted.peer_id, "peer-real");
        assert_eq!(promoted.device_name, "ThinkPad X1");
        assert_eq!(promoted.platform, "linux");
        assert_eq!(promoted.paired_at, provisional.paired_at);
        assert!(store.peer(&provisional.peer_id).is_none());
    }

    #[test]
    fn test_promote_provisional_is_a_noop_for_unknown_fingerprint() {
        let store = TrustStore::in_memory();
        store
            .promote_provisional("not-a-known-fp", "peer-x", "Device", "linux")
            .unwrap();
        assert!(store.is_empty());
    }
}

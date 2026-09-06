//! Paired-device trust store and the pinned-fingerprint TLS verifier.
//!
//! Shunkan has no certificate authority and no web PKI. A peer is trusted iff
//! the BLAKE3 fingerprint of the certificate it presents was recorded in this
//! store at pairing time. That is the whole trust model, and it is what
//! [`PinnedFingerprintVerifier`] enforces during the TLS handshake.
//!
//! Both directions are enforced: [`PinnedFingerprintVerifier`] checks the peer
//! a client dials, and [`PinnedClientCertVerifier`] checks the peer a server
//! accepts. That is mutual TLS against the paired-device store — an
//! unauthorized device is refused during the handshake rather than after it.
//!
//! ## Pairing mode, and why a pin is not a pairing
//!
//! An empty store can never grow if unknown certificates are always rejected,
//! so the store carries an explicit *pairing mode* flag. While it is on, an
//! unknown certificate is **provisionally** pinned; while it is off — the
//! default — an unknown fingerprint aborts the handshake.
//!
//! A provisional pin buys exactly one thing: the ability to run the PIN
//! exchange in [`crate::pairing`] over that channel. It is not operational
//! trust. [`TrustStore::is_trusted_fingerprint`] returns `false` for it until
//! [`TrustStore::confirm`] records a successful PAKE, and a failed exchange
//! calls [`TrustStore::forget_unconfirmed_fingerprint`] so nothing usable is
//! left behind.
//!
//! Without that distinction, "pairing mode" would just be "trust anyone who
//! connects while the window is open" — which is the hole the PIN is supposed
//! to close.

use crate::identity::fingerprint_of;
use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
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
    /// Whether the PIN exchange completed for this pairing.
    ///
    /// A certificate pinned during trust-on-first-use starts **unconfirmed**:
    /// it is enough to carry the pairing exchange itself and nothing more.
    /// Only a successful PAKE confirmation makes a device operationally
    /// trusted. Without this distinction, "pairing mode" would just be "trust
    /// anyone who connects while the window is open".
    #[serde(default = "confirmed_by_default")]
    pub confirmed: bool,
}

/// Entries written before this field existed were created by an explicit
/// `pair()` call, which is a confirmed pairing.
fn confirmed_by_default() -> bool {
    true
}

impl PairedPeer {
    /// Record a new, confirmed pairing, stamped with the current time.
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
            confirmed: true,
        }
    }

    /// Record a provisional pairing — pinned, but not yet PIN-confirmed.
    pub fn provisional(fingerprint: impl Into<String>) -> Self {
        let fingerprint = fingerprint.into();
        let short = &fingerprint[..fingerprint.len().min(16)];
        Self {
            peer_id: format!("unconfirmed-{}", short),
            device_name: "unconfirmed".to_string(),
            platform: "unknown".to_string(),
            paired_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            fingerprint,
            confirmed: false,
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

    /// Open or close the pairing window.
    ///
    /// While open, an unknown certificate is provisionally pinned so the PIN
    /// exchange can run over it. It does not become operationally trusted
    /// without a successful [`TrustStore::confirm`].
    pub fn set_pairing_mode(&self, enabled: bool) {
        let mut state = self.lock();
        state.pairing_mode = enabled;
        if enabled {
            log::warn!(
                "Pairing window OPEN — unknown devices may attempt a PIN pairing until it closes"
            );
        } else {
            log::info!("Pairing window closed — only paired devices are accepted");
        }
    }

    /// Whether the pairing window is currently open.
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

    /// Whether this fingerprint belongs to a **confirmed** paired device.
    ///
    /// A provisionally pinned certificate is not trusted here: it can carry a
    /// pairing exchange and nothing else.
    pub fn is_trusted_fingerprint(&self, fingerprint: &str) -> bool {
        self.peer_by_fingerprint(fingerprint)
            .is_some_and(|peer| peer.confirmed)
    }

    /// Whether this fingerprint is pinned at all, confirmed or not.
    pub fn is_pinned_fingerprint(&self, fingerprint: &str) -> bool {
        self.lock().by_fingerprint.contains_key(fingerprint)
    }

    /// Drop a provisional pin by fingerprint. Confirmed pairings are left alone.
    ///
    /// Called when a pairing exchange fails, so a failed attempt does not leave
    /// a usable pin behind.
    pub fn forget_unconfirmed_fingerprint(&self, fingerprint: &str) -> Result<bool> {
        let Some(peer) = self.peer_by_fingerprint(fingerprint) else {
            return Ok(false);
        };
        if peer.confirmed {
            return Ok(false);
        }

        log::warn!(
            "Dropping unconfirmed pin for fingerprint {}…",
            &fingerprint[..fingerprint.len().min(16)]
        );
        self.lock().remove(&peer.peer_id);
        self.save()?;
        Ok(true)
    }

    /// Mark a provisionally pinned certificate as a confirmed pairing, filling
    /// in the peer metadata carried by the handshake.
    pub fn confirm(
        &self,
        fingerprint: &str,
        peer_id: &str,
        device_name: &str,
        platform: &str,
    ) -> Result<()> {
        let existing = self.peer_by_fingerprint(fingerprint);
        let paired_at = existing.as_ref().map(|p| p.paired_at).unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });

        {
            let mut state = self.lock();
            if let Some(existing) = existing {
                state.remove(&existing.peer_id);
            }
            state.insert(PairedPeer {
                peer_id: peer_id.to_string(),
                device_name: device_name.to_string(),
                platform: platform.to_string(),
                fingerprint: fingerprint.to_string(),
                paired_at,
                confirmed: true,
            });
        }

        log::info!(
            "Pairing confirmed with {} ({}) — fingerprint {}… is now trusted",
            device_name,
            peer_id,
            &fingerprint[..fingerprint.len().min(16)]
        );
        self.save()
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
    pub(crate) fn authorize_certificate(
        &self,
        cert: &CertificateDer<'_>,
    ) -> Result<String, TlsError> {
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

        // Pairing mode: pin provisionally so the PIN exchange can run over the
        // channel. Until that exchange confirms, this certificate buys nothing
        // else — `is_trusted_fingerprint` still says no.
        log::warn!(
            "Pairing mode: provisionally pinning unseen fingerprint {}… (unconfirmed until the PIN exchange succeeds)",
            &fingerprint[..16]
        );
        self.lock().insert(PairedPeer::provisional(&fingerprint));
        if let Err(e) = self.save() {
            log::error!("Failed to persist provisional pin: {}", e);
        }
        Ok(fingerprint)
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

/// A [`ClientCertVerifier`] that accepts an inbound peer iff its certificate
/// fingerprint is pinned in the [`TrustStore`].
///
/// This is the server-side half of mutual TLS. Without it, `accept()` returned
/// every incoming connection with no validation at all — a clipboard any
/// machine on a café Wi-Fi could read from and inject into. Rejecting here
/// means an unauthorized peer never completes a handshake, rather than being
/// turned away after one.
#[derive(Debug)]
pub struct PinnedClientCertVerifier {
    trust: Arc<TrustStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// Empty: we have no CA subjects to hint, because there is no CA.
    root_hints: Vec<DistinguishedName>,
}

impl PinnedClientCertVerifier {
    /// Build a verifier backed by the given trust store.
    pub fn new(trust: Arc<TrustStore>) -> Self {
        Self {
            trust,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            root_hints: Vec::new(),
        }
    }
}

impl ClientCertVerifier for PinnedClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        self.trust.authorize_certificate(end_entity)?;
        Ok(ClientCertVerified::assertion())
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
    fn test_unknown_certificate_pinned_provisionally_in_pairing_mode() {
        let identity = DeviceIdentity::generate().unwrap();
        let store = TrustStore::in_memory();
        store.set_pairing_mode(true);

        let fp = store.authorize_certificate(identity.cert_der()).unwrap();
        assert_eq!(fp, identity.fingerprint());

        // Pinned, so the PIN exchange can run over the channel…
        assert!(store.is_pinned_fingerprint(identity.fingerprint()));
        // …but a pin is not a pairing.
        assert!(!store.is_trusted_fingerprint(identity.fingerprint()));

        // The pin survives the window closing, so the exchange in flight can
        // still complete.
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
    fn test_confirm_replaces_provisional_metadata_and_grants_trust() {
        let identity = DeviceIdentity::generate().unwrap();
        let store = TrustStore::in_memory();
        store.set_pairing_mode(true);
        store.authorize_certificate(identity.cert_der()).unwrap();

        let provisional = store.peer_by_fingerprint(identity.fingerprint()).unwrap();
        assert_eq!(provisional.platform, "unknown");
        assert!(!provisional.confirmed);
        assert!(!store.is_trusted_fingerprint(identity.fingerprint()));

        store
            .confirm(identity.fingerprint(), "peer-real", "ThinkPad X1", "linux")
            .unwrap();

        assert_eq!(store.len(), 1);
        let confirmed = store.peer_by_fingerprint(identity.fingerprint()).unwrap();
        assert_eq!(confirmed.peer_id, "peer-real");
        assert_eq!(confirmed.device_name, "ThinkPad X1");
        assert_eq!(confirmed.platform, "linux");
        assert_eq!(confirmed.paired_at, provisional.paired_at);
        assert!(confirmed.confirmed);
        assert!(store.is_trusted_fingerprint(identity.fingerprint()));
        assert!(store.peer(&provisional.peer_id).is_none());
    }

    #[test]
    fn test_confirm_works_for_a_fingerprint_that_was_never_pinned() {
        let store = TrustStore::in_memory();
        store
            .confirm("fp-new", "peer-x", "Device", "linux")
            .unwrap();
        assert!(store.is_trusted_fingerprint("fp-new"));
    }

    /// A provisional pin buys exactly one thing: the ability to run the PIN
    /// exchange. Without this, "pairing mode" would be "trust anyone who
    /// connects while the window is open".
    #[test]
    fn test_provisional_pin_is_not_operational_trust() {
        let identity = DeviceIdentity::generate().unwrap();
        let store = TrustStore::in_memory();
        store.set_pairing_mode(true);
        store.authorize_certificate(identity.cert_der()).unwrap();

        assert!(store.is_pinned_fingerprint(identity.fingerprint()));
        assert!(!store.is_trusted_fingerprint(identity.fingerprint()));
    }

    /// A failed pairing must not leave a usable pin behind.
    #[test]
    fn test_failed_pairing_drops_the_provisional_pin() {
        let identity = DeviceIdentity::generate().unwrap();
        let store = TrustStore::in_memory();
        store.set_pairing_mode(true);
        store.authorize_certificate(identity.cert_der()).unwrap();

        assert!(store
            .forget_unconfirmed_fingerprint(identity.fingerprint())
            .unwrap());
        assert!(!store.is_pinned_fingerprint(identity.fingerprint()));
        assert!(store.is_empty());

        // And with pairing mode off, the certificate is refused again.
        store.set_pairing_mode(false);
        assert!(store.authorize_certificate(identity.cert_der()).is_err());
    }

    /// Dropping unconfirmed pins must never touch a real pairing.
    #[test]
    fn test_forgetting_unconfirmed_leaves_confirmed_pairings_alone() {
        let store = TrustStore::in_memory();
        store
            .pair(PairedPeer::new("peer-1", "Phone", "android", "fp-1"))
            .unwrap();

        assert!(!store.forget_unconfirmed_fingerprint("fp-1").unwrap());
        assert!(store.is_trusted_fingerprint("fp-1"));
        assert!(!store.forget_unconfirmed_fingerprint("never-seen").unwrap());
    }

    #[test]
    fn test_pinned_but_unconfirmed_peers_are_not_reported_as_trusted() {
        let store = TrustStore::in_memory();
        store
            .pair(PairedPeer::new("p", "D", "linux", "fp-ok"))
            .unwrap();
        store.set_pairing_mode(true);
        let identity = DeviceIdentity::generate().unwrap();
        store.authorize_certificate(identity.cert_der()).unwrap();

        assert_eq!(store.len(), 2, "both records are stored");
        assert!(store.is_trusted_fingerprint("fp-ok"));
        assert!(!store.is_trusted_fingerprint(identity.fingerprint()));
    }
}

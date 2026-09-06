//! Persistent device identity — peer ID, TLS certificate, and private key.
//!
//! Shunkan's trust model is fingerprint pinning, not a certificate authority:
//! each device mints one long-lived self-signed certificate, persists it, and
//! peers trust each other by the BLAKE3 fingerprint of that certificate
//! recorded at pairing time (see [`crate::trust`]).
//!
//! This is what makes REQ-CORE-02's "silent future reconnects" possible. If the
//! identity were regenerated per process (or worse, per call, as it was before),
//! every restart would present a brand-new certificate and every paired device
//! would see a stranger.
//!
//! ## On-disk layout
//!
//! Under `$XDG_DATA_HOME/shunkan` (default `~/.local/share/shunkan`):
//!
//! ```text
//! device.crt.der    self-signed certificate, DER            0644
//! device.key.der    PKCS#8 private key, DER                 0600
//! peer_id           stable peer identifier, UTF-8           0644
//! paired_peers.json trust store (see crate::trust)          0600
//! ```

use crate::protocol::PeerId;
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::{Path, PathBuf};

/// Filename of the persisted certificate.
pub const CERT_FILE: &str = "device.crt.der";
/// Filename of the persisted private key.
pub const KEY_FILE: &str = "device.key.der";
/// Filename of the persisted peer identifier.
pub const PEER_ID_FILE: &str = "peer_id";

/// Resolve the directory Shunkan stores its identity and trust state in.
///
/// Follows the XDG Base Directory spec: `$XDG_DATA_HOME/shunkan`, falling back
/// to `$HOME/.local/share/shunkan`, and finally to `./.shunkan` if neither
/// environment variable is set.
pub fn default_data_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("shunkan");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".local/share/shunkan");
        }
    }
    PathBuf::from(".shunkan")
}

/// Compute the BLAKE3 fingerprint of a certificate, as a lowercase hex string.
///
/// This is the value pinned at pairing time and checked on every subsequent
/// connection. It is a public value — it identifies a device, it does not
/// authenticate one on its own.
pub fn fingerprint_of(cert: &CertificateDer<'_>) -> String {
    crate::hashing::hash_bytes(cert.as_ref())
}

/// A device's long-lived cryptographic identity.
///
/// Created once and persisted; loaded on every subsequent start.
pub struct DeviceIdentity {
    peer_id: PeerId,
    cert_der: CertificateDer<'static>,
    key_der: PrivateKeyDer<'static>,
    fingerprint: String,
}

impl DeviceIdentity {
    /// Mint a brand-new identity in memory without persisting it.
    ///
    /// Prefer [`DeviceIdentity::load_or_create`] outside of tests — an identity
    /// that is not persisted defeats the entire point of having one.
    pub fn generate() -> Result<Self> {
        let peer_id = PeerId::random();
        Self::generate_with_peer_id(peer_id)
    }

    /// Mint a new identity bound to a specific peer ID.
    pub fn generate_with_peer_id(peer_id: PeerId) -> Result<Self> {
        let dns_name = dns_name_for(&peer_id);
        let cert_params = rcgen::CertificateParams::new(vec![dns_name])
            .context("Failed to create certificate params")?;
        let key_pair = rcgen::KeyPair::generate().context("Failed to generate key pair")?;
        let cert = cert_params
            .self_signed(&key_pair)
            .context("Failed to self-sign certificate")?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
            .map_err(|e| anyhow::anyhow!("Failed to encode private key DER: {}", e))?;
        let fingerprint = fingerprint_of(&cert_der);

        Ok(Self {
            peer_id,
            cert_der,
            key_der,
            fingerprint,
        })
    }

    /// Load the identity from `dir`, creating and persisting one if absent.
    ///
    /// A partially written identity (certificate present but key missing, or
    /// vice versa) is treated as absent and regenerated.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        if let Some(existing) = Self::load(dir)? {
            log::info!(
                "Loaded device identity {} (fingerprint {}…)",
                existing.peer_id,
                &existing.fingerprint[..16]
            );
            return Ok(existing);
        }

        let identity = Self::generate()?;
        identity.save(dir)?;
        log::info!(
            "Created device identity {} (fingerprint {}…) in {}",
            identity.peer_id,
            &identity.fingerprint[..16],
            dir.display()
        );
        Ok(identity)
    }

    /// Load a persisted identity from `dir`, or `Ok(None)` if none exists.
    pub fn load(dir: &Path) -> Result<Option<Self>> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        let id_path = dir.join(PEER_ID_FILE);

        if !cert_path.exists() || !key_path.exists() || !id_path.exists() {
            return Ok(None);
        }

        let cert_bytes = std::fs::read(&cert_path)
            .with_context(|| format!("Failed to read {}", cert_path.display()))?;
        let key_bytes = std::fs::read(&key_path)
            .with_context(|| format!("Failed to read {}", key_path.display()))?;
        let peer_id_raw = std::fs::read_to_string(&id_path)
            .with_context(|| format!("Failed to read {}", id_path.display()))?;

        let peer_id = PeerId::new(peer_id_raw.trim());
        anyhow::ensure!(
            !peer_id.0.is_empty(),
            "Persisted peer ID at {} is empty",
            id_path.display()
        );

        let cert_der = CertificateDer::from(cert_bytes);
        let key_der = PrivateKeyDer::try_from(key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse persisted private key: {}", e))?;
        let fingerprint = fingerprint_of(&cert_der);

        Ok(Some(Self {
            peer_id,
            cert_der,
            key_der,
            fingerprint,
        }))
    }

    /// Persist this identity to `dir`, creating the directory if needed.
    ///
    /// The private key is written with mode `0600` on Unix.
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create data directory {}", dir.display()))?;
        restrict_dir_permissions(dir)?;

        std::fs::write(dir.join(CERT_FILE), self.cert_der.as_ref())
            .context("Failed to write device certificate")?;
        std::fs::write(dir.join(PEER_ID_FILE), self.peer_id.0.as_bytes())
            .context("Failed to write peer ID")?;

        let key_path = dir.join(KEY_FILE);
        std::fs::write(&key_path, self.key_der.secret_der())
            .context("Failed to write device private key")?;
        restrict_file_permissions(&key_path)?;

        Ok(())
    }

    /// This device's stable peer identifier.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// The BLAKE3 fingerprint of this device's certificate, as hex.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// This device's certificate in DER form.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// A clone of this device's private key.
    pub fn key_der(&self) -> PrivateKeyDer<'static> {
        self.key_der.clone_key()
    }

    /// The DNS name in this device's certificate SAN.
    ///
    /// Peers use it as the TLS server name when connecting. Certificate
    /// *validation* is by pinned fingerprint, so this name is an identifier,
    /// not a security boundary.
    pub fn dns_name(&self) -> String {
        dns_name_for(&self.peer_id)
    }
}

impl std::fmt::Debug for DeviceIdentity {
    /// Deliberately omits the private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("peer_id", &self.peer_id)
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

/// Build the certificate SAN / TLS server name for a peer ID.
pub fn dns_name_for(peer_id: &PeerId) -> String {
    // PeerId::random() produces "peer-<16 hex>", which is a valid DNS label.
    // Sanitize anyway so a caller-supplied ID can't produce an invalid SAN.
    let label: String = peer_id
        .0
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let label = if label.is_empty() {
        "unknown".to_string()
    } else {
        label
    };
    format!("{}.shunkan.local", label)
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

#[cfg(unix)]
fn restrict_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("Failed to set 0700 permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_dir_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shunkan-identity-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_generate_produces_fingerprint() {
        let id = DeviceIdentity::generate().unwrap();
        assert_eq!(id.fingerprint().len(), 64);
        assert!(id.peer_id().0.starts_with("peer-"));
    }

    #[test]
    fn test_distinct_identities_have_distinct_fingerprints() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn test_identity_persists_across_loads() {
        let dir = temp_dir("persist");
        let first = DeviceIdentity::load_or_create(&dir).unwrap();
        let second = DeviceIdentity::load_or_create(&dir).unwrap();

        // This is the whole point of F-19: a restart must be the same device.
        assert_eq!(first.peer_id(), second.peer_id());
        assert_eq!(first.fingerprint(), second.fingerprint());
        assert_eq!(first.cert_der(), second.cert_der());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_missing_identity_loads_as_none() {
        let dir = temp_dir("absent");
        assert!(DeviceIdentity::load(&dir).unwrap().is_none());
    }

    #[test]
    fn test_partial_identity_is_treated_as_absent() {
        let dir = temp_dir("partial");
        let id = DeviceIdentity::generate().unwrap();
        id.save(&dir).unwrap();
        std::fs::remove_file(dir.join(KEY_FILE)).unwrap();

        assert!(DeviceIdentity::load(&dir).unwrap().is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_private_key_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("perms");
        let id = DeviceIdentity::generate().unwrap();
        id.save(&dir).unwrap();

        let mode = std::fs::metadata(dir.join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "private key must be 0600, was {:o}", mode);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_dns_name_is_derived_from_peer_id() {
        let id = DeviceIdentity::generate_with_peer_id(PeerId::new("peer-abc123")).unwrap();
        assert_eq!(id.dns_name(), "peer-abc123.shunkan.local");
    }

    #[test]
    fn test_dns_name_sanitizes_unusual_ids() {
        assert_eq!(
            dns_name_for(&PeerId::new("weird id/../x")),
            "weird-id----x.shunkan.local"
        );
        assert_eq!(dns_name_for(&PeerId::new("")), "unknown.shunkan.local");
    }

    #[test]
    fn test_fingerprint_matches_blake3_of_cert() {
        let id = DeviceIdentity::generate().unwrap();
        let expected = crate::hashing::hash_bytes(id.cert_der().as_ref());
        assert_eq!(id.fingerprint(), expected);
    }

    #[test]
    fn test_debug_does_not_leak_private_key() {
        let id = DeviceIdentity::generate().unwrap();
        let rendered = format!("{:?}", id);
        assert!(rendered.contains("fingerprint"));
        assert!(!rendered.contains("key_der"));
    }
}

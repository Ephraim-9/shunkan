//! X25519 key exchange scaffold and PIN verification.
//!
//! Provides PIN-based pairing verification using BLAKE3 hashing, a scaffold for
//! future X25519 Diffie-Hellman key exchange, and the QUIC/TLS configuration
//! that binds a [`DeviceIdentity`] to a [`TrustStore`].
//!
//! ## Why there is no `generate_self_signed_cert()` any more
//!
//! There used to be one, and it minted a fresh keypair on every call while
//! building a client config whose root store contained *that same certificate*.
//! Server and client each called it independently, so the client trusted a
//! certificate the server had never seen and every handshake died with
//! `BadSignature`. Certificates now come from a persisted [`DeviceIdentity`],
//! and peer trust comes from fingerprints pinned in the [`TrustStore`].

use crate::identity::DeviceIdentity;
use crate::trust::{PinnedFingerprintVerifier, TrustStore};
use anyhow::{Context, Result};
use std::sync::Arc;

/// Install the ring crypto provider exactly once per process.
///
/// `install_default` errors if a provider is already installed, which is a
/// benign race when several endpoints start concurrently; `Once` makes the
/// outcome deterministic instead.
fn install_crypto_provider() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A 6-digit PIN used for device pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingPin(String);

impl PairingPin {
    /// Generate a random 6-digit PIN.
    pub fn generate() -> Self {
        use rand::Rng;
        let pin: u32 = rand::thread_rng().gen_range(0..1_000_000);
        Self(format!("{:06}", pin))
    }

    /// Parse a PairingPin from a string. Returns an error if the PIN is not
    /// exactly 6 digits.
    ///
    /// Also available as [`std::str::FromStr`], so `"123456".parse()` works.
    pub fn parse(pin: &str) -> Result<Self> {
        anyhow::ensure!(pin.len() == 6, "PIN must be exactly 6 digits");
        anyhow::ensure!(
            pin.chars().all(|c| c.is_ascii_digit()),
            "PIN must contain only digits"
        );
        Ok(Self(pin.to_string()))
    }

    /// Get the PIN as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Compute a BLAKE3 hash of the PIN for secure comparison.
    /// The hash includes a domain separator to prevent cross-protocol attacks.
    pub fn hash(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"shunkan-pin-v1:");
        hasher.update(self.0.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Verify that a given hash matches this PIN's hash.
    pub fn verify_hash(&self, hash: &str) -> bool {
        self.hash() == hash
    }
}

impl std::str::FromStr for PairingPin {
    type Err = anyhow::Error;

    fn from_str(pin: &str) -> Result<Self> {
        Self::parse(pin)
    }
}

impl std::fmt::Display for PairingPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display as XXX-XXX for readability
        write!(f, "{}-{}", &self.0[..3], &self.0[3..])
    }
}

/// Build the rustls server config presenting this device's persisted identity.
///
/// Client authentication is not required here yet; connections are authorized
/// by the handshake exchange in [`crate::transport`]. Mutual TLS against the
/// paired-device store is a separate change.
pub fn server_tls_config(identity: &DeviceIdentity) -> Result<rustls::ServerConfig> {
    install_crypto_provider();

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![identity.cert_der().clone()], identity.key_der())
        .context("Failed to build server TLS config from device identity")
}

/// Build the rustls client config that pins peers by certificate fingerprint.
///
/// The verifier accepts a peer iff its fingerprint is recorded in `trust` (or
/// `trust` is in pairing mode). No web PKI roots are consulted.
pub fn client_tls_config(trust: Arc<TrustStore>) -> Result<rustls::ClientConfig> {
    install_crypto_provider();

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedFingerprintVerifier::new(trust)))
        .with_no_client_auth();

    Ok(config)
}

/// Build a quinn server config from this device's identity.
pub fn quinn_server_config(identity: &DeviceIdentity) -> Result<quinn::ServerConfig> {
    let tls = server_tls_config(identity)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC server config: {}", e))?,
    )))
}

/// Build a quinn client config that pins peers by certificate fingerprint.
pub fn quinn_client_config(trust: Arc<TrustStore>) -> Result<quinn::ClientConfig> {
    let tls = client_tls_config(trust)?;
    Ok(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC client config: {}", e))?,
    )))
}

/// Placeholder for future X25519 key pair generation.
///
/// In the full implementation, this would use `x25519-dalek` to generate
/// ephemeral Diffie-Hellman key pairs for additional encryption layer
/// negotiation beyond TLS.
pub struct KeyPair {
    /// The public key bytes (32 bytes for X25519).
    pub public_key: Vec<u8>,
    // Private key would be stored here in the full implementation
}

impl KeyPair {
    /// Generate a placeholder key pair.
    ///
    /// **NOTE**: This is a scaffold. The full implementation will use
    /// `x25519-dalek` for proper Diffie-Hellman key exchange.
    pub fn generate_placeholder() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut public_key = vec![0u8; 32];
        rng.fill(&mut public_key[..]);
        Self { public_key }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_generate() {
        let pin = PairingPin::generate();
        assert_eq!(pin.as_str().len(), 6);
        assert!(pin.as_str().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_pin_from_str_valid() {
        let pin = PairingPin::parse("123456").unwrap();
        assert_eq!(pin.as_str(), "123456");
    }

    #[test]
    fn test_pin_from_str_invalid_length() {
        assert!(PairingPin::parse("12345").is_err());
        assert!(PairingPin::parse("1234567").is_err());
    }

    #[test]
    fn test_pin_from_str_non_digits() {
        assert!(PairingPin::parse("12345a").is_err());
        assert!(PairingPin::parse("abcdef").is_err());
    }

    #[test]
    fn test_pin_display() {
        let pin = PairingPin::parse("123456").unwrap();
        assert_eq!(format!("{}", pin), "123-456");
    }

    #[test]
    fn test_pin_parses_via_from_str_trait() {
        let pin: PairingPin = "654321".parse().unwrap();
        assert_eq!(pin.as_str(), "654321");
        assert!("nope".parse::<PairingPin>().is_err());
    }

    #[test]
    fn test_pin_hash_deterministic() {
        let pin = PairingPin::parse("000000").unwrap();
        let h1 = pin.hash();
        let h2 = pin.hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // BLAKE3 hex
    }

    #[test]
    fn test_pin_hash_different_pins() {
        let pin1 = PairingPin::parse("000000").unwrap();
        let pin2 = PairingPin::parse("000001").unwrap();
        assert_ne!(pin1.hash(), pin2.hash());
    }

    #[test]
    fn test_pin_verify_hash() {
        let pin = PairingPin::parse("654321").unwrap();
        let hash = pin.hash();
        assert!(pin.verify_hash(&hash));
        assert!(!pin.verify_hash("wrong_hash"));
    }

    #[test]
    fn test_pin_hash_uses_blake3_not_sha256() {
        // Verify that the hash is BLAKE3 (64 hex chars) and NOT a SHA-256 hash.
        // Both are 64 hex chars, but we verify BLAKE3 by checking against a known value.
        let pin = PairingPin::parse("123456").unwrap();
        let hash = pin.hash();
        assert_eq!(hash.len(), 64);

        // Verify it matches BLAKE3 computation directly
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"shunkan-pin-v1:");
        hasher.update(b"123456");
        let expected = hasher.finalize().to_hex().to_string();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_server_tls_config_from_identity() {
        let identity = DeviceIdentity::generate().unwrap();
        let result = server_tls_config(&identity);
        assert!(
            result.is_ok(),
            "Server TLS config failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_client_tls_config_from_trust_store() {
        let trust = Arc::new(TrustStore::in_memory());
        let result = client_tls_config(trust);
        assert!(
            result.is_ok(),
            "Client TLS config failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_quinn_configs_build_from_identity_and_trust() {
        let identity = DeviceIdentity::generate().unwrap();
        let trust = Arc::new(TrustStore::in_memory());
        assert!(quinn_server_config(&identity).is_ok());
        assert!(quinn_client_config(trust).is_ok());
    }

    #[test]
    fn test_key_pair_placeholder() {
        let kp = KeyPair::generate_placeholder();
        assert_eq!(kp.public_key.len(), 32);
    }
}

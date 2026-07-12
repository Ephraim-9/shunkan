//! X25519 key exchange scaffold and PIN verification.
//!
//! Provides utilities for generating self-signed TLS certificates (via `rcgen`),
//! PIN-based pairing verification using BLAKE3 hashing, and a scaffold for
//! future X25519 Diffie-Hellman key exchange.

use anyhow::{Context, Result};
use std::sync::Arc;

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

    /// Create a PairingPin from a string. Returns an error if the PIN is not
    /// exactly 6 digits.
    pub fn from_str(pin: &str) -> Result<Self> {
        anyhow::ensure!(pin.len() == 6, "PIN must be exactly 6 digits");
        anyhow::ensure!(pin.chars().all(|c| c.is_ascii_digit()), "PIN must contain only digits");
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

impl std::fmt::Display for PairingPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Display as XXX-XXX for readability
        write!(f, "{}-{}", &self.0[..3], &self.0[3..])
    }
}

/// Generate a self-signed TLS certificate and private key for QUIC transport.
///
/// The certificate uses the `rcgen` crate and is valid for localhost connections.
/// Returns a `rustls::ServerConfig` wrapped in an `Arc` suitable for use with `quinn`.
pub fn generate_self_signed_cert() -> Result<(rustls::ServerConfig, rustls::ClientConfig)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // Generate a self-signed certificate
    let cert_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .context("Failed to create certificate params")?;
    let key_pair = rcgen::KeyPair::generate().context("Failed to generate key pair")?;
    let cert = cert_params
        .self_signed(&key_pair)
        .context("Failed to self-sign certificate")?;

    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
            .map_err(|e| anyhow::anyhow!("Failed to create private key DER: {}", e))?;

    // Build server config
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.clone_key())
        .context("Failed to build server TLS config")?;

    // Build client config that trusts our self-signed cert
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(cert_der)
        .context("Failed to add cert to root store")?;

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok((server_config, client_config))
}

/// Generate quinn-compatible server and client configs from self-signed certs.
pub fn generate_quinn_configs() -> Result<(quinn::ServerConfig, quinn::ClientConfig)> {
    let (server_tls, client_tls) = generate_self_signed_cert()?;

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC server config: {}", e))?,
    ));

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_tls)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC client config: {}", e))?,
    ));

    Ok((server_config, client_config))
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
        let pin = PairingPin::from_str("123456").unwrap();
        assert_eq!(pin.as_str(), "123456");
    }

    #[test]
    fn test_pin_from_str_invalid_length() {
        assert!(PairingPin::from_str("12345").is_err());
        assert!(PairingPin::from_str("1234567").is_err());
    }

    #[test]
    fn test_pin_from_str_non_digits() {
        assert!(PairingPin::from_str("12345a").is_err());
        assert!(PairingPin::from_str("abcdef").is_err());
    }

    #[test]
    fn test_pin_display() {
        let pin = PairingPin::from_str("123456").unwrap();
        assert_eq!(format!("{}", pin), "123-456");
    }

    #[test]
    fn test_pin_hash_deterministic() {
        let pin = PairingPin::from_str("000000").unwrap();
        let h1 = pin.hash();
        let h2 = pin.hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // BLAKE3 hex
    }

    #[test]
    fn test_pin_hash_different_pins() {
        let pin1 = PairingPin::from_str("000000").unwrap();
        let pin2 = PairingPin::from_str("000001").unwrap();
        assert_ne!(pin1.hash(), pin2.hash());
    }

    #[test]
    fn test_pin_verify_hash() {
        let pin = PairingPin::from_str("654321").unwrap();
        let hash = pin.hash();
        assert!(pin.verify_hash(&hash));
        assert!(!pin.verify_hash("wrong_hash"));
    }

    #[test]
    fn test_pin_hash_uses_blake3_not_sha256() {
        // Verify that the hash is BLAKE3 (64 hex chars) and NOT a SHA-256 hash.
        // Both are 64 hex chars, but we verify BLAKE3 by checking against a known value.
        let pin = PairingPin::from_str("123456").unwrap();
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
    fn test_generate_self_signed_cert() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok(), "Certificate generation failed: {:?}", result.err());
    }

    #[test]
    fn test_generate_quinn_configs() {
        let result = generate_quinn_configs();
        assert!(
            result.is_ok(),
            "Quinn config generation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_key_pair_placeholder() {
        let kp = KeyPair::generate_placeholder();
        assert_eq!(kp.public_key.len(), 32);
    }
}

//! The pairing PIN type and the QUIC/TLS configuration that binds a
//! [`DeviceIdentity`] to a [`TrustStore`].
//!
//! The PIN is *authenticated* in [`crate::pairing`], via SPAKE2. This module
//! only defines and validates the value.
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
use crate::trust::{PinnedClientCertVerifier, PinnedFingerprintVerifier, TrustStore};
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
    ///
    /// The only legitimate consumers are the user-facing display and
    /// [`crate::pairing::PairingSession::start`]. The PIN itself must never
    /// reach the wire.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    // `hash()` and `verify_hash()` used to live here, producing an unsalted
    // BLAKE3("shunkan-pin-v1:" || pin) that was carried in the handshake. Over
    // a six-digit space all 10^6 candidates enumerate in milliseconds, so
    // anyone who sniffed one handshake recovered the PIN — and the value was
    // static, so it replayed. They are gone rather than merely unused: leaving
    // the primitive in a crypto module invites it back onto the wire.
    // See `crate::pairing` for what replaced them.
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

/// Build the rustls server config for mutual TLS against the paired-device store.
///
/// Client authentication is **mandatory**: an inbound peer whose certificate
/// fingerprint is not pinned is rejected during the handshake rather than
/// after it. `accept()` used to return every incoming connection with no
/// validation at all, against a server built `with_no_client_auth()`.
pub fn server_tls_config(
    identity: &DeviceIdentity,
    trust: Arc<TrustStore>,
) -> Result<rustls::ServerConfig> {
    install_crypto_provider();

    rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(PinnedClientCertVerifier::new(trust)))
        .with_single_cert(vec![identity.cert_der().clone()], identity.key_der())
        .context("Failed to build server TLS config from device identity")
}

/// Build the rustls client config that pins peers by certificate fingerprint.
///
/// The verifier accepts a peer iff its fingerprint is recorded in `trust` (or
/// `trust` is in pairing mode). No web PKI roots are consulted. The client also
/// presents its own certificate, so the peer can authenticate us in turn — the
/// other half of mutual TLS.
pub fn client_tls_config(
    identity: &DeviceIdentity,
    trust: Arc<TrustStore>,
) -> Result<rustls::ClientConfig> {
    install_crypto_provider();

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedFingerprintVerifier::new(trust)))
        .with_client_auth_cert(vec![identity.cert_der().clone()], identity.key_der())
        .context("Failed to build client TLS config from device identity")
}

/// Build a quinn server config from this device's identity and trust store.
pub fn quinn_server_config(
    identity: &DeviceIdentity,
    trust: Arc<TrustStore>,
) -> Result<quinn::ServerConfig> {
    let tls = server_tls_config(identity, trust)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC server config: {}", e))?,
    )))
}

/// Build a quinn client config that pins peers by certificate fingerprint.
pub fn quinn_client_config(
    identity: &DeviceIdentity,
    trust: Arc<TrustStore>,
) -> Result<quinn::ClientConfig> {
    let tls = client_tls_config(identity, trust)?;
    Ok(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC client config: {}", e))?,
    )))
}

// The X25519 `KeyPair` scaffold that used to live here has been removed.
//
// It filled a 32-byte vector from the RNG and called it `public_key`. There was
// no private key, no curve operation, and no Diffie-Hellman — and
// `x25519-dalek` was not even a dependency. But it was a `pub` type named
// `KeyPair` with a `public_key` field, which is exactly the shape a caller
// would trust. A convincing-looking fake in a crypto module is worse than an
// absence.
//
// The key agreement it gestured at is now real and lives in
// [`crate::pairing`]: SPAKE2 over the pairing PIN, yielding a shared key bound
// to both TLS certificate fingerprints. If a separate DH layer is ever wanted
// on top of TLS 1.3, it should be added then, with `x25519-dalek`, and used.

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
    fn test_pin_space_is_small_enough_to_need_a_pake() {
        // Documents why the old scheme was broken rather than merely weak: a
        // six-digit PIN is 10^6 candidates, which is trivially enumerable
        // against any hash an eavesdropper can grind offline. See
        // `crate::pairing` for the exchange that never exposes it.
        let pin = PairingPin::generate();
        assert_eq!(pin.as_str().len(), 6);
        assert!(pin.as_str().parse::<u32>().unwrap() < 1_000_000);
    }

    #[test]
    fn test_server_tls_config_from_identity() {
        let identity = DeviceIdentity::generate().unwrap();
        let trust = Arc::new(TrustStore::in_memory());
        let result = server_tls_config(&identity, trust);
        assert!(
            result.is_ok(),
            "Server TLS config failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_client_tls_config_from_trust_store() {
        let identity = DeviceIdentity::generate().unwrap();
        let trust = Arc::new(TrustStore::in_memory());
        let result = client_tls_config(&identity, trust);
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
        assert!(quinn_server_config(&identity, trust.clone()).is_ok());
        assert!(quinn_client_config(&identity, trust).is_ok());
    }
}

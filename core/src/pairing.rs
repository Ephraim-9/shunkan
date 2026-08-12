//! PIN-authenticated pairing using SPAKE2, bound to TLS certificate fingerprints.
//!
//! ## What was here before
//!
//! The wire carried an unsalted `BLAKE3("shunkan-pin-v1:" || pin)` over a
//! six-digit space. All 10^6 candidates enumerate in milliseconds, so anyone
//! who sniffed one handshake recovered the PIN — and the value was static, so
//! it replayed. More fundamentally, no code anywhere read `Handshake.pin_hash`:
//! there was no verification path, no attempt limit, and no pairing state
//! machine at all. REQ-CORE-02 was unimplemented.
//!
//! ## What happens now
//!
//! A PAKE. Both devices run SPAKE2 over the six-digit PIN and derive a shared
//! key without ever putting the PIN, or anything enumerable from it, on the
//! wire. An eavesdropper learns nothing they can grind offline; an active
//! attacker gets exactly one online guess per attempt, and
//! [`AttemptLimiter`] bounds how many of those they get.
//!
//! The derived key is then bound to **both** TLS certificate fingerprints in a
//! confirmation MAC. That is what stops a machine-in-the-middle: an attacker
//! who relays the SPAKE2 exchange between two honest devices terminates two
//! different TLS connections, so the fingerprints it can prove differ from the
//! ones each side sees, and both confirmations fail.
//!
//! ```text
//!   A (dialer/initiator)                     B (listener/responder)
//!   ── SPAKE2 start_a(pin, idA, idB) ─────►  ── SPAKE2 start_b(...) ──
//!            PairingHello { spake } ─────────────────►
//!            ◄───────────────────── PairingHello { spake }
//!   both derive K = SPAKE2.finish(peer_msg)
//!   MAC_x = BLAKE3_keyed(K, domain ‖ role_x ‖ fp_A ‖ fp_B)
//!            PairingConfirm { mac_A } ───────────────►   verify
//!            ◄───────────────── PairingConfirm { mac_B }  verify
//! ```
//!
//! Both MACs are compared in constant time via [`subtle::ConstantTimeEq`].

use crate::crypto::PairingPin;
use anyhow::{bail, ensure, Context, Result};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

/// Domain separator for the confirmation MAC.
const MAC_DOMAIN: &str = "shunkan-pairing-confirm-v1";

/// Domain separator for deriving the MAC key from the SPAKE2 output.
const KEY_DERIVATION_CONTEXT: &str = "shunkan 2026-01-01 pairing confirmation key";

/// SPAKE2 protocol identity, so a Shunkan exchange cannot be cross-protocolled.
const PROTOCOL_IDENTITY: &str = "shunkan-pairing-v1";

/// Failed PIN attempts allowed before a peer is locked out.
pub const MAX_PAIRING_ATTEMPTS: u32 = 5;

/// How long a peer stays locked out after exhausting its attempts.
pub const PAIRING_LOCKOUT: Duration = Duration::from_secs(300);

/// Which side of the pairing exchange this device is.
///
/// Derived from who dialled, so both devices agree without negotiating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingRole {
    /// The device that dialled. SPAKE2 side A.
    Initiator,
    /// The device that accepted. SPAKE2 side B.
    Responder,
}

impl PairingRole {
    fn tag(self) -> &'static str {
        match self {
            PairingRole::Initiator => "initiator",
            PairingRole::Responder => "responder",
        }
    }

    /// The tag the peer will use, so each side can check the other's MAC.
    fn peer_tag(self) -> &'static str {
        match self {
            PairingRole::Initiator => "responder",
            PairingRole::Responder => "initiator",
        }
    }
}

/// The TLS certificate fingerprints the pairing is bound to.
///
/// Both sides must compute the same pair — one from their own identity, one
/// from the certificate the peer presented — or the confirmation fails. This is
/// what a relaying attacker cannot satisfy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelBinding {
    /// Certificate fingerprint of the device that dialled.
    pub initiator_fingerprint: String,
    /// Certificate fingerprint of the device that accepted.
    pub responder_fingerprint: String,
}

impl ChannelBinding {
    /// Build a binding from this device's role and the two fingerprints.
    pub fn new(
        role: PairingRole,
        our_fingerprint: impl Into<String>,
        peer_fingerprint: impl Into<String>,
    ) -> Self {
        let (ours, theirs) = (our_fingerprint.into(), peer_fingerprint.into());
        match role {
            PairingRole::Initiator => Self {
                initiator_fingerprint: ours,
                responder_fingerprint: theirs,
            },
            PairingRole::Responder => Self {
                initiator_fingerprint: theirs,
                responder_fingerprint: ours,
            },
        }
    }
}

/// An in-progress SPAKE2 exchange.
///
/// Not `Clone` and consumed by [`PairingSession::finish`]: a SPAKE2 state must
/// be used exactly once.
pub struct PairingSession {
    state: Spake2<Ed25519Group>,
    role: PairingRole,
    binding: ChannelBinding,
    outbound: Vec<u8>,
}

impl PairingSession {
    /// Begin a pairing exchange, returning the session and the message to send.
    ///
    /// `initiator_id` and `responder_id` are the two peer IDs, exchanged in the
    /// preceding handshake. Both sides must pass them in the same order.
    pub fn start(
        pin: &PairingPin,
        role: PairingRole,
        initiator_id: &str,
        responder_id: &str,
        binding: ChannelBinding,
    ) -> Self {
        let password = Password::new(pin.as_str().as_bytes());
        let id_a = Identity::new(format!("{}:{}", PROTOCOL_IDENTITY, initiator_id).as_bytes());
        let id_b = Identity::new(format!("{}:{}", PROTOCOL_IDENTITY, responder_id).as_bytes());

        let (state, outbound) = match role {
            PairingRole::Initiator => Spake2::<Ed25519Group>::start_a(&password, &id_a, &id_b),
            PairingRole::Responder => Spake2::<Ed25519Group>::start_b(&password, &id_a, &id_b),
        };

        Self {
            state,
            role,
            binding,
            outbound,
        }
    }

    /// The SPAKE2 message to send to the peer.
    pub fn outbound_message(&self) -> &[u8] {
        &self.outbound
    }

    /// This device's role in the exchange.
    pub fn role(&self) -> PairingRole {
        self.role
    }

    /// Complete the exchange with the peer's SPAKE2 message.
    ///
    /// Rejects a message identical to our own — a reflection, which is the
    /// classic way to attack a symmetric PAKE.
    pub fn finish(self, peer_message: &[u8]) -> Result<PairingConfirmation> {
        ensure!(
            !peer_message.is_empty(),
            "Peer sent an empty SPAKE2 message"
        );
        ensure!(
            peer_message != self.outbound.as_slice(),
            "Peer reflected our own SPAKE2 message back at us"
        );

        let shared = self
            .state
            .finish(peer_message)
            .map_err(|e| anyhow::anyhow!("SPAKE2 exchange failed: {:?}", e))
            .context("The peer used a different PIN, or the exchange was tampered with")?;

        // SPAKE2's output is not a uniformly random key on its own; run it
        // through a KDF with a context string before using it as a MAC key.
        let key = blake3::derive_key(KEY_DERIVATION_CONTEXT, &shared);

        Ok(PairingConfirmation {
            key,
            role: self.role,
            binding: self.binding,
        })
    }
}

impl std::fmt::Debug for PairingSession {
    /// Deliberately omits the SPAKE2 state.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingSession")
            .field("role", &self.role)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

/// A completed SPAKE2 exchange, ready to prove and verify key confirmation.
pub struct PairingConfirmation {
    key: [u8; 32],
    role: PairingRole,
    binding: ChannelBinding,
}

impl PairingConfirmation {
    /// The MAC this device sends to prove it derived the same key.
    pub fn our_mac(&self) -> String {
        self.mac_for(self.role.tag())
    }

    /// Verify the peer's MAC in constant time.
    ///
    /// A `==` on hex strings leaks, through timing, how many leading bytes
    /// matched — which is a usable oracle when an attacker can retry.
    pub fn verify_peer_mac(&self, peer_mac: &str) -> bool {
        let expected = self.mac_for(self.role.peer_tag());
        if expected.len() != peer_mac.len() {
            return false;
        }
        expected.as_bytes().ct_eq(peer_mac.as_bytes()).into()
    }

    /// The derived pairing key, for callers that need to bind further state to
    /// it. Not needed for the pairing flow itself.
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    fn mac_for(&self, role_tag: &str) -> String {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(MAC_DOMAIN.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(role_tag.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(self.binding.initiator_fingerprint.as_bytes());
        transcript.push(0);
        transcript.extend_from_slice(self.binding.responder_fingerprint.as_bytes());

        blake3::keyed_hash(&self.key, &transcript)
            .to_hex()
            .to_string()
    }
}

impl std::fmt::Debug for PairingConfirmation {
    /// Deliberately omits the derived key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingConfirmation")
            .field("role", &self.role)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Attempts {
    failures: u32,
    locked_until: Option<Instant>,
}

/// Bounds how many PIN guesses a peer gets.
///
/// A PAKE reduces an attacker to one online guess per exchange. Over a
/// six-digit space that is still 10^6 exchanges, so the guesses have to be
/// rationed as well.
#[derive(Debug, Default)]
pub struct AttemptLimiter {
    attempts: Mutex<HashMap<String, Attempts>>,
}

impl AttemptLimiter {
    /// Create an empty limiter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether `key` (a peer ID or fingerprint) may attempt a pairing.
    pub fn check(&self, key: &str) -> Result<()> {
        self.check_at(key, Instant::now())
    }

    /// Record a failed attempt, locking the peer out once it runs out.
    pub fn record_failure(&self, key: &str) {
        self.record_failure_at(key, Instant::now())
    }

    /// Clear a peer's failure count after a successful pairing.
    pub fn record_success(&self, key: &str) {
        self.lock().remove(key);
    }

    /// Failed attempts recorded for `key`.
    pub fn failures(&self, key: &str) -> u32 {
        self.lock().get(key).map_or(0, |a| a.failures)
    }

    fn check_at(&self, key: &str, now: Instant) -> Result<()> {
        let mut attempts = self.lock();
        let Some(entry) = attempts.get_mut(key) else {
            return Ok(());
        };

        match entry.locked_until {
            Some(until) if until > now => {
                bail!(
                    "Too many failed pairing attempts; locked out for another {}s",
                    (until - now).as_secs() + 1
                );
            }
            Some(_) => {
                // The lockout expired; the peer starts over with a full budget.
                attempts.remove(key);
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn record_failure_at(&self, key: &str, now: Instant) {
        let mut attempts = self.lock();
        let entry = attempts.entry(key.to_string()).or_insert(Attempts {
            failures: 0,
            locked_until: None,
        });
        entry.failures = entry.failures.saturating_add(1);

        if entry.failures >= MAX_PAIRING_ATTEMPTS {
            entry.locked_until = Some(now + PAIRING_LOCKOUT);
            log::warn!(
                "Locking out {} after {} failed pairing attempts",
                key,
                entry.failures
            );
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Attempts>> {
        self.attempts.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "aaaa1111bbbb2222cccc3333dddd4444";
    const FP_B: &str = "eeee5555ffff6666aaaa7777bbbb8888";

    /// Run a full exchange between two sides that agree on everything.
    fn exchange(
        pin_a: &PairingPin,
        pin_b: &PairingPin,
        binding_a: ChannelBinding,
        binding_b: ChannelBinding,
    ) -> Result<(PairingConfirmation, PairingConfirmation)> {
        let a = PairingSession::start(pin_a, PairingRole::Initiator, "peer-a", "peer-b", binding_a);
        let b = PairingSession::start(pin_b, PairingRole::Responder, "peer-a", "peer-b", binding_b);

        let msg_a = a.outbound_message().to_vec();
        let msg_b = b.outbound_message().to_vec();

        Ok((a.finish(&msg_b)?, b.finish(&msg_a)?))
    }

    fn matching_bindings() -> (ChannelBinding, ChannelBinding) {
        (
            ChannelBinding::new(PairingRole::Initiator, FP_A, FP_B),
            ChannelBinding::new(PairingRole::Responder, FP_B, FP_A),
        )
    }

    #[test]
    fn test_matching_pins_produce_mutually_verifiable_macs() {
        let pin = PairingPin::parse("314159").unwrap();
        let (ba, bb) = matching_bindings();
        let (conf_a, conf_b) = exchange(&pin, &pin, ba, bb).unwrap();

        assert!(conf_b.verify_peer_mac(&conf_a.our_mac()));
        assert!(conf_a.verify_peer_mac(&conf_b.our_mac()));
        assert_eq!(conf_a.key(), conf_b.key(), "both sides derive one key");
    }

    #[test]
    fn test_role_bindings_agree_on_fingerprint_order() {
        let (ba, bb) = matching_bindings();
        assert_eq!(ba, bb, "both sides must order the fingerprints identically");
        assert_eq!(ba.initiator_fingerprint, FP_A);
        assert_eq!(ba.responder_fingerprint, FP_B);
    }

    #[test]
    fn test_mismatched_pins_fail() {
        let (ba, bb) = matching_bindings();
        let result = exchange(
            &PairingPin::parse("111111").unwrap(),
            &PairingPin::parse("222222").unwrap(),
            ba,
            bb,
        );

        // SPAKE2 either errors outright or yields different keys; both sides'
        // MACs must not verify either way.
        match result {
            Err(_) => {}
            Ok((conf_a, conf_b)) => {
                assert_ne!(conf_a.key(), conf_b.key());
                assert!(!conf_b.verify_peer_mac(&conf_a.our_mac()));
                assert!(!conf_a.verify_peer_mac(&conf_b.our_mac()));
            }
        }
    }

    /// The machine-in-the-middle case. The relay terminates two different TLS
    /// connections, so the fingerprints it can prove are not the ones the
    /// honest peers see, and confirmation fails even though the PIN matched.
    #[test]
    fn test_mismatched_channel_binding_fails_confirmation() {
        let pin = PairingPin::parse("424242").unwrap();
        let honest = ChannelBinding::new(PairingRole::Initiator, FP_A, FP_B);
        let relayed = ChannelBinding::new(PairingRole::Responder, FP_B, "attacker-fingerprint");

        let (conf_a, conf_b) = exchange(&pin, &pin, honest, relayed).unwrap();

        assert_eq!(conf_a.key(), conf_b.key(), "the PAKE itself still succeeds");
        assert!(
            !conf_b.verify_peer_mac(&conf_a.our_mac()),
            "a relayed exchange must not confirm"
        );
        assert!(!conf_a.verify_peer_mac(&conf_b.our_mac()));
    }

    #[test]
    fn test_a_side_mac_is_not_accepted_as_the_b_side_mac() {
        let pin = PairingPin::parse("999999").unwrap();
        let (ba, bb) = matching_bindings();
        let (conf_a, conf_b) = exchange(&pin, &pin, ba, bb).unwrap();

        // Replaying our own MAC back at us must not verify.
        assert!(!conf_a.verify_peer_mac(&conf_a.our_mac()));
        assert!(!conf_b.verify_peer_mac(&conf_b.our_mac()));
    }

    #[test]
    fn test_reflected_spake_message_is_rejected() {
        let pin = PairingPin::parse("123456").unwrap();
        let (ba, _) = matching_bindings();
        let session = PairingSession::start(&pin, PairingRole::Initiator, "peer-a", "peer-b", ba);

        let own = session.outbound_message().to_vec();
        let err = session.finish(&own).unwrap_err();
        assert!(err.to_string().contains("reflected"));
    }

    #[test]
    fn test_empty_spake_message_is_rejected() {
        let pin = PairingPin::parse("123456").unwrap();
        let (ba, _) = matching_bindings();
        let session = PairingSession::start(&pin, PairingRole::Initiator, "peer-a", "peer-b", ba);
        assert!(session.finish(&[]).is_err());
    }

    #[test]
    fn test_garbage_spake_message_is_rejected() {
        let pin = PairingPin::parse("123456").unwrap();
        let (ba, _) = matching_bindings();
        let session = PairingSession::start(&pin, PairingRole::Initiator, "peer-a", "peer-b", ba);
        assert!(session.finish(b"not a spake2 message").is_err());
    }

    #[test]
    fn test_wrong_length_mac_is_rejected_without_panicking() {
        let pin = PairingPin::parse("123456").unwrap();
        let (ba, bb) = matching_bindings();
        let (conf_a, _) = exchange(&pin, &pin, ba, bb).unwrap();

        assert!(!conf_a.verify_peer_mac(""));
        assert!(!conf_a.verify_peer_mac("short"));
        assert!(!conf_a.verify_peer_mac(&"f".repeat(1000)));
    }

    #[test]
    fn test_the_pin_never_appears_in_the_wire_message() {
        let pin = PairingPin::parse("867530").unwrap();
        let (ba, _) = matching_bindings();
        let session = PairingSession::start(&pin, PairingRole::Initiator, "peer-a", "peer-b", ba);

        let wire = session.outbound_message();
        assert!(!wire.windows(6).any(|w| w == b"867530"));
        // And nothing enumerable from it: the old scheme put
        // BLAKE3("shunkan-pin-v1:" || pin) straight on the wire.
        let old_hash = blake3::Hasher::new()
            .update(b"shunkan-pin-v1:")
            .update(b"867530")
            .finalize()
            .to_hex()
            .to_string();
        assert!(!wire.windows(32).any(|w| w == &old_hash.as_bytes()[..32]));
    }

    #[test]
    fn test_debug_impls_do_not_leak_secrets() {
        let pin = PairingPin::parse("135791").unwrap();
        let (ba, bb) = matching_bindings();
        let session =
            PairingSession::start(&pin, PairingRole::Initiator, "peer-a", "peer-b", ba.clone());
        let rendered = format!("{:?}", session);
        assert!(!rendered.contains("135791"));
        assert!(!rendered.contains("state"));

        let (conf, _) = exchange(&pin, &pin, ba, bb).unwrap();
        let rendered = format!("{:?}", conf);
        assert!(!rendered.contains("key"));
    }

    // ── Attempt limiting ─────────────────────────────────────────────────────

    #[test]
    fn test_limiter_allows_attempts_until_the_budget_runs_out() {
        let limiter = AttemptLimiter::new();
        let start = Instant::now();

        for _ in 0..MAX_PAIRING_ATTEMPTS - 1 {
            assert!(limiter.check_at("peer-1", start).is_ok());
            limiter.record_failure_at("peer-1", start);
        }
        assert!(limiter.check_at("peer-1", start).is_ok());

        limiter.record_failure_at("peer-1", start);
        assert_eq!(limiter.failures("peer-1"), MAX_PAIRING_ATTEMPTS);
        assert!(limiter.check_at("peer-1", start).is_err());
    }

    #[test]
    fn test_lockout_expires() {
        let limiter = AttemptLimiter::new();
        let start = Instant::now();

        for _ in 0..MAX_PAIRING_ATTEMPTS {
            limiter.record_failure_at("peer-1", start);
        }
        assert!(limiter.check_at("peer-1", start).is_err());

        let after = start + PAIRING_LOCKOUT + Duration::from_secs(1);
        assert!(limiter.check_at("peer-1", after).is_ok());
        assert_eq!(limiter.failures("peer-1"), 0, "budget resets after lockout");
    }

    #[test]
    fn test_success_clears_the_failure_count() {
        let limiter = AttemptLimiter::new();
        limiter.record_failure("peer-1");
        limiter.record_failure("peer-1");
        assert_eq!(limiter.failures("peer-1"), 2);

        limiter.record_success("peer-1");
        assert_eq!(limiter.failures("peer-1"), 0);
        assert!(limiter.check("peer-1").is_ok());
    }

    #[test]
    fn test_limiter_is_per_peer() {
        let limiter = AttemptLimiter::new();
        let start = Instant::now();

        for _ in 0..MAX_PAIRING_ATTEMPTS {
            limiter.record_failure_at("noisy", start);
        }

        assert!(limiter.check_at("noisy", start).is_err());
        assert!(limiter.check_at("innocent", start).is_ok());
    }
}

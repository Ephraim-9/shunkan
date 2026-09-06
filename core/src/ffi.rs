//! UniFFI bindings for the Android (and any future non-Rust) frontend.
//!
//! INV-04 requires UniFFI for FFI bindings. There was none: no `uniffi`
//! dependency, no `.udl`, no proc-macro exports, no build script, no bindgen
//! step — and `core/Cargo.toml` declared no `crate-type`, so the crate built as
//! an rlib only and `libshunkan_core.so` could never exist. The Gradle comment
//! pointing at `jniLibs/` described a file nothing generated.
//!
//! This module is the exported surface: **discovery, pairing, send, and a
//! receive callback** — the four things the Android client needs from the
//! engine. It composes the same primitives the Linux daemon uses, so there is
//! one implementation of the protocol, not two.
//!
//! ## What this is not
//!
//! Not the whole daemon. Android's *capture* path is deliberately not here: see
//! the module docs in `mobile-android` and ADR-006 for why clipboard reads on
//! Android 10+ are user-initiated by design. This surface is what a
//! `ShunkanIME` / `ShareTarget` calls into once the user has acted.

use crate::crypto::PairingPin;
use crate::discovery::{DiscoveryEvent, DiscoveryService, ServiceAdvertisement};
use crate::history::ClipboardHistory;
use crate::identity::{self, DeviceIdentity};
use crate::pairing::{AttemptLimiter, ChannelBinding, PairingRole, PairingSession};
use crate::protocol::{ClipboardItem, Handshake, Message, PeerId, PeerInfo};
use crate::transport::{ControlChannel, TransportClient, TransportConfig, TransportServer};
use crate::trust::{PairedPeer, TrustStore};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// How long a peer has to complete the handshake before we hang up.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long each step of the pairing exchange may take.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors crossing the FFI boundary.
///
/// Deliberately coarse: a Kotlin caller needs to know what to tell the user,
/// not the internal error chain. The full chain is logged on the Rust side.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ShunkanError {
    /// The device identity or trust store could not be read or written.
    #[error("storage error: {reason}")]
    Storage {
        /// What went wrong.
        reason: String,
    },
    /// The network stack failed to start or a connection failed.
    #[error("network error: {reason}")]
    Network {
        /// What went wrong.
        reason: String,
    },
    /// Pairing was refused: wrong PIN, rate limited, or a relayed channel.
    #[error("pairing failed: {reason}")]
    Pairing {
        /// What went wrong.
        reason: String,
    },
    /// The requested peer is not known or not reachable.
    #[error("no such peer: {peer_id}")]
    UnknownPeer {
        /// The peer that was asked for.
        peer_id: String,
    },
    /// The engine was used before `start()` or after `stop()`.
    #[error("engine is not running")]
    NotRunning,
    /// The argument was not valid (a malformed PIN, say).
    #[error("invalid argument: {reason}")]
    InvalidArgument {
        /// What went wrong.
        reason: String,
    },
}

impl ShunkanError {
    fn storage(e: impl std::fmt::Display) -> Self {
        Self::Storage {
            reason: e.to_string(),
        }
    }
    fn network(e: impl std::fmt::Display) -> Self {
        Self::Network {
            reason: e.to_string(),
        }
    }
    fn pairing(e: impl std::fmt::Display) -> Self {
        Self::Pairing {
            reason: e.to_string(),
        }
    }
}

/// A peer as seen by the frontend.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiPeer {
    /// The peer's stable identifier.
    pub peer_id: String,
    /// Human-readable device name.
    pub device_name: String,
    /// Platform identifier.
    pub platform: String,
    /// Whether a connection is currently established.
    pub connected: bool,
    /// Whether this device has completed a PIN pairing with the peer.
    pub paired: bool,
}

/// A clipboard entry as seen by the frontend.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiClipboardEntry {
    /// BLAKE3 content hash.
    pub hash: String,
    /// The text content. Non-text entries are not surfaced here yet.
    pub text: String,
    /// When it was copied (seconds since UNIX epoch).
    pub timestamp: u64,
    /// The peer it came from.
    pub source_peer: String,
}

/// Callbacks the frontend implements to receive engine events.
///
/// This is the "receive-callback" half of the surface. It replaces polling
/// entirely, which matters more on Android than anywhere else: INV-03 prohibits
/// polling loops on Android threads.
#[uniffi::export(with_foreign)]
pub trait ShunkanListener: Send + Sync {
    /// A peer sent us clipboard text.
    fn on_clipboard_received(&self, text: String, source_peer: String);
    /// A peer connected or disconnected.
    fn on_peers_changed(&self);
    /// A pairing attempt finished.
    fn on_pairing_result(&self, peer_id: String, accepted: bool, reason: Option<String>);
    /// Something went wrong in the background.
    fn on_error(&self, message: String);
}

/// A connected peer's outbound queue.
struct PeerLink {
    info: PeerInfo,
    tx: mpsc::UnboundedSender<ClipboardItem>,
}

/// Mutable engine state, guarded together so it cannot get out of step.
#[derive(Default)]
struct EngineState {
    peers: HashMap<String, PeerLink>,
    running: bool,
}

/// The Shunkan engine, as exposed to non-Rust callers.
///
/// Owns the device identity, trust store, discovery, and peer connections.
/// Every method is safe to call from any thread.
#[derive(uniffi::Object)]
pub struct ShunkanEngine {
    identity: Arc<DeviceIdentity>,
    trust: Arc<TrustStore>,
    peer_info: PeerInfo,
    history: Mutex<ClipboardHistory>,
    state: Mutex<EngineState>,
    pairing_pin: Mutex<Option<PairingPin>>,
    attempts: AttemptLimiter,
    runtime: tokio::runtime::Runtime,
    listener: Mutex<Option<Arc<dyn ShunkanListener>>>,
}

#[uniffi::export]
impl ShunkanEngine {
    /// Create an engine, loading or creating this device's identity in `data_dir`.
    ///
    /// On Android pass `context.filesDir.absolutePath`.
    #[uniffi::constructor]
    pub fn new(data_dir: String, device_name: String) -> Result<Arc<Self>, ShunkanError> {
        let dir = PathBuf::from(data_dir);
        let identity =
            Arc::new(DeviceIdentity::load_or_create(&dir).map_err(ShunkanError::storage)?);
        let trust = Arc::new(TrustStore::load_or_create(&dir).map_err(ShunkanError::storage)?);
        let peer_info = PeerInfo::new(identity.peer_id().clone(), device_name, "android");

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("shunkan-engine")
            .build()
            .map_err(ShunkanError::network)?;

        Ok(Arc::new(Self {
            identity,
            trust,
            peer_info,
            history: Mutex::new(ClipboardHistory::with_default_capacity()),
            state: Mutex::new(EngineState::default()),
            pairing_pin: Mutex::new(None),
            attempts: AttemptLimiter::new(),
            runtime,
            listener: Mutex::new(None),
        }))
    }

    /// This device's stable peer ID.
    pub fn peer_id(&self) -> String {
        self.peer_info.id.0.clone()
    }

    /// This device's certificate fingerprint, for display during pairing.
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint().to_string()
    }

    /// Start listening, advertising, and browsing for peers.
    pub fn start(self: Arc<Self>, listener: Arc<dyn ShunkanListener>) -> Result<(), ShunkanError> {
        {
            let mut state = self.lock_state();
            if state.running {
                return Ok(());
            }
            state.running = true;
        }
        *self.listener.lock().unwrap_or_else(|e| e.into_inner()) = Some(listener);

        let engine = Arc::clone(&self);
        let started = self.runtime.block_on(async move {
            let server = TransportServer::start(
                TransportConfig {
                    bind_addr: ([0, 0, 0, 0], crate::DEFAULT_PORT).into(),
                    ..TransportConfig::default()
                },
                &engine.identity,
                engine.trust.clone(),
            )
            .await?;
            let port = server.local_addr()?.port();

            let accept_engine = Arc::clone(&engine);
            tokio::spawn(async move {
                accept_engine.accept_loop(server).await;
            });

            let discover_engine = Arc::clone(&engine);
            tokio::spawn(async move {
                if let Err(e) = discover_engine.clone().discovery_loop(port).await {
                    discover_engine.report_error(format!("discovery stopped: {}", e));
                }
            });

            Ok::<(), anyhow::Error>(())
        });

        if let Err(e) = started {
            self.lock_state().running = false;
            return Err(ShunkanError::network(e));
        }
        Ok(())
    }

    /// Stop accepting new work. Existing connections wind down on their own.
    pub fn stop(&self) {
        let mut state = self.lock_state();
        state.running = false;
        state.peers.clear();
    }

    /// Whether the engine is running.
    pub fn is_running(&self) -> bool {
        self.lock_state().running
    }

    /// Open a pairing window with the given six-digit PIN.
    ///
    /// The other device must be showing, or be given, the same PIN.
    pub fn begin_pairing(&self, pin: String) -> Result<(), ShunkanError> {
        let pin = PairingPin::parse(pin.trim()).map_err(|e| ShunkanError::InvalidArgument {
            reason: e.to_string(),
        })?;
        *self.pairing_pin.lock().unwrap_or_else(|e| e.into_inner()) = Some(pin);
        self.trust.set_pairing_mode(true);
        Ok(())
    }

    /// Generate a PIN to display, and open a pairing window for it.
    pub fn begin_pairing_with_generated_pin(&self) -> String {
        let pin = PairingPin::generate();
        let shown = pin.as_str().to_string();
        *self.pairing_pin.lock().unwrap_or_else(|e| e.into_inner()) = Some(pin);
        self.trust.set_pairing_mode(true);
        shown
    }

    /// Close the pairing window.
    pub fn end_pairing(&self) {
        *self.pairing_pin.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.trust.set_pairing_mode(false);
    }

    /// Peers this device knows about — connected, paired, or both.
    pub fn peers(&self) -> Vec<FfiPeer> {
        let state = self.lock_state();
        let mut peers: HashMap<String, FfiPeer> = HashMap::new();

        for paired in self.trust.paired_peers() {
            if !paired.confirmed {
                continue;
            }
            peers.insert(
                paired.peer_id.clone(),
                FfiPeer {
                    peer_id: paired.peer_id,
                    device_name: paired.device_name,
                    platform: paired.platform,
                    connected: false,
                    paired: true,
                },
            );
        }

        for (id, link) in state.peers.iter() {
            let entry = peers.entry(id.clone()).or_insert_with(|| FfiPeer {
                peer_id: id.clone(),
                device_name: link.info.device_name.clone(),
                platform: link.info.platform.clone(),
                connected: false,
                paired: false,
            });
            entry.connected = true;
            entry.device_name = link.info.device_name.clone();
            entry.platform = link.info.platform.clone();
        }

        peers.into_values().collect()
    }

    /// Send clipboard text to every connected peer.
    ///
    /// Returns how many peers it was queued for.
    pub fn send_clipboard(&self, text: String) -> Result<u32, ShunkanError> {
        if !self.is_running() {
            return Err(ShunkanError::NotRunning);
        }

        let item = ClipboardItem::from_text(text, self.peer_info.id.clone());
        self.record(item.clone());

        let mut delivered = 0u32;
        let mut dead = Vec::new();
        {
            let state = self.lock_state();
            for (id, link) in state.peers.iter() {
                if link.tx.send(item.clone()).is_ok() {
                    delivered += 1;
                } else {
                    dead.push(id.clone());
                }
            }
        }
        if !dead.is_empty() {
            let mut state = self.lock_state();
            for id in dead {
                state.peers.remove(&id);
            }
        }

        Ok(delivered)
    }

    /// Send clipboard text to one peer.
    pub fn send_clipboard_to(&self, peer_id: String, text: String) -> Result<(), ShunkanError> {
        if !self.is_running() {
            return Err(ShunkanError::NotRunning);
        }

        let item = ClipboardItem::from_text(text, self.peer_info.id.clone());
        self.record(item.clone());

        let link_tx = {
            let state = self.lock_state();
            state.peers.get(&peer_id).map(|link| link.tx.clone())
        };

        match link_tx {
            Some(tx) if tx.send(item).is_ok() => Ok(()),
            _ => Err(ShunkanError::UnknownPeer { peer_id }),
        }
    }

    /// The most recent clipboard entries, newest first.
    pub fn history(&self, limit: u32) -> Vec<FfiClipboardEntry> {
        self.lock_history()
            .items()
            .take(limit as usize)
            .filter_map(|item| {
                Some(FfiClipboardEntry {
                    hash: item.content_hash.clone(),
                    text: String::from_utf8(item.data.clone()).ok()?,
                    timestamp: item.timestamp,
                    source_peer: item.source_peer.0.clone(),
                })
            })
            .collect()
    }

    /// Forget a paired device.
    pub fn forget_peer(&self, peer_id: String) -> Result<(), ShunkanError> {
        self.trust
            .forget(&peer_id)
            .map_err(ShunkanError::storage)
            .map(|_| ())?;
        self.lock_state().peers.remove(&peer_id);
        Ok(())
    }
}

// ── Internals, not exported across the FFI boundary ──────────────────────────

impl ShunkanEngine {
    fn lock_state(&self) -> std::sync::MutexGuard<'_, EngineState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_history(&self) -> std::sync::MutexGuard<'_, ClipboardHistory> {
        self.history.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn listener(&self) -> Option<Arc<dyn ShunkanListener>> {
        self.listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn record(&self, item: ClipboardItem) {
        self.lock_history().push(item);
    }

    fn report_error(&self, message: String) {
        log::warn!("{}", message);
        if let Some(listener) = self.listener() {
            listener.on_error(message);
        }
    }

    fn notify_peers_changed(&self) {
        if let Some(listener) = self.listener() {
            listener.on_peers_changed();
        }
    }

    /// Accept inbound connections until the endpoint closes.
    async fn accept_loop(self: Arc<Self>, server: TransportServer) {
        loop {
            if !self.is_running() {
                server.shutdown();
                return;
            }
            match server.accept().await {
                Ok(Some(conn)) => {
                    let engine = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = engine.clone().serve(conn, false).await {
                            log::debug!("Inbound connection ended: {}", e);
                        }
                    });
                }
                Ok(None) => return,
                Err(e) => log::debug!("Rejected inbound connection: {}", e),
            }
        }
    }

    /// Advertise, browse, and dial discovered peers.
    async fn discovery_loop(self: Arc<Self>, port: u16) -> anyhow::Result<()> {
        let mut discovery = DiscoveryService::new()?;
        let mut events = discovery.browse()?;

        let advertisement = ServiceAdvertisement::new(
            self.peer_info.id.0.clone(),
            "android",
            self.identity.fingerprint(),
        );
        let instance = sanitize_instance_name(&self.peer_info.device_name);
        discovery.register(&instance, port, &advertisement)?;

        let client = Arc::new(TransportClient::new(&self.identity, self.trust.clone())?);

        while let Some(event) = events.recv().await {
            if !self.is_running() {
                return Ok(());
            }
            let DiscoveryEvent::PeerDiscovered(peer) = event else {
                continue;
            };
            let Some(ad) = peer.advertisement.clone() else {
                continue;
            };
            if self.lock_state().peers.contains_key(&ad.peer_id) {
                continue;
            }
            // Same tie-break the desktop uses, so exactly one side dials.
            if self.peer_info.id.0 >= ad.peer_id {
                continue;
            }
            let Some(addr) = peer.socket_addr() else {
                continue;
            };

            let engine = Arc::clone(&self);
            let client = Arc::clone(&client);
            let server_name = identity::dns_name_for(&PeerId::new(ad.peer_id.clone()));
            tokio::spawn(async move {
                match client.connect(addr, &server_name).await {
                    Ok(conn) => {
                        if let Err(e) = engine.clone().serve(conn, true).await {
                            log::debug!("Outbound connection ended: {}", e);
                        }
                    }
                    Err(e) => log::debug!("Could not dial {}: {}", ad.peer_id, e),
                }
            });
        }

        Ok(())
    }

    /// Handshake, pair if needed, then pump the connection.
    async fn serve(
        self: Arc<Self>,
        conn: crate::transport::TransportConnection,
        dialed: bool,
    ) -> anyhow::Result<()> {
        let fingerprint = conn
            .peer_fingerprint()
            .ok_or_else(|| anyhow::anyhow!("peer presented no certificate"))?;

        let mut control = if dialed {
            conn.open_control().await?
        } else {
            conn.accept_control().await?
        };

        control
            .send(&Message::Handshake(Handshake::new(self.peer_info.clone())))
            .await?;
        let peer_info = match tokio::time::timeout(HANDSHAKE_TIMEOUT, control.recv()).await?? {
            Message::Handshake(hs) => hs.peer_info,
            other => anyhow::bail!("expected a handshake, got {:?}", other),
        };
        anyhow::ensure!(
            peer_info.id != self.peer_info.id,
            "refusing to connect to ourselves"
        );

        if !self.trust.is_trusted_fingerprint(&fingerprint) {
            let outcome = self
                .run_pairing(&mut control, &peer_info, &fingerprint, dialed)
                .await;
            let accepted = outcome.is_ok();
            let reason = outcome.as_ref().err().map(|e| e.to_string());

            if let Some(listener) = self.listener() {
                listener.on_pairing_result(peer_info.id.0.clone(), accepted, reason);
            }
            if let Err(e) = outcome {
                let _ = self.trust.forget_unconfirmed_fingerprint(&fingerprint);
                conn.close();
                return Err(e);
            }
        }

        let (mut sender, mut receiver) = control.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<ClipboardItem>();
        let peer_key = peer_info.id.0.clone();

        self.lock_state().peers.insert(
            peer_key.clone(),
            PeerLink {
                info: peer_info.clone(),
                tx,
            },
        );
        self.notify_peers_changed();

        let writer = tokio::spawn(async move {
            while let Some(item) = rx.recv().await {
                if sender.send_clipboard(item).await.is_err() {
                    break;
                }
            }
            let _ = sender.finish();
        });

        while let Ok(msg) = receiver.recv().await {
            if let Message::Clipboard { item, .. } = msg {
                if let Ok(text) = String::from_utf8(item.data.clone()) {
                    let source = item.source_peer.0.clone();
                    self.record(item);
                    if let Some(listener) = self.listener() {
                        listener.on_clipboard_received(text, source);
                    }
                }
            }
        }

        self.lock_state().peers.remove(&peer_key);
        self.notify_peers_changed();
        writer.abort();
        conn.close();
        Ok(())
    }

    /// The SPAKE2 PIN exchange, mirroring the desktop implementation.
    async fn run_pairing(
        &self,
        control: &mut ControlChannel,
        peer_info: &PeerInfo,
        peer_fingerprint: &str,
        dialed: bool,
    ) -> anyhow::Result<()> {
        let pin = self
            .pairing_pin
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no pairing PIN is set; call begin_pairing first"))?;

        self.attempts.check(&peer_info.id.0)?;

        let role = if dialed {
            PairingRole::Initiator
        } else {
            PairingRole::Responder
        };
        let (initiator, responder) = match role {
            PairingRole::Initiator => (self.peer_info.id.0.clone(), peer_info.id.0.clone()),
            PairingRole::Responder => (peer_info.id.0.clone(), self.peer_info.id.0.clone()),
        };
        let binding = ChannelBinding::new(role, self.identity.fingerprint(), peer_fingerprint);

        let session = PairingSession::start(&pin, role, &initiator, &responder, binding);
        control
            .send(&Message::PairingHello {
                spake: session.outbound_message().to_vec(),
            })
            .await?;

        let peer_spake = match tokio::time::timeout(PAIRING_TIMEOUT, control.recv()).await?? {
            Message::PairingHello { spake } => spake,
            other => anyhow::bail!("expected a pairing message, got {:?}", other),
        };

        let confirmation = match session.finish(&peer_spake) {
            Ok(c) => c,
            Err(e) => {
                self.attempts.record_failure(&peer_info.id.0);
                return Err(e);
            }
        };

        control
            .send(&Message::PairingConfirm {
                mac: confirmation.our_mac(),
            })
            .await?;
        let peer_mac = match tokio::time::timeout(PAIRING_TIMEOUT, control.recv()).await?? {
            Message::PairingConfirm { mac } => mac,
            other => anyhow::bail!("expected a pairing confirmation, got {:?}", other),
        };

        if !confirmation.verify_peer_mac(&peer_mac) {
            self.attempts.record_failure(&peer_info.id.0);
            anyhow::bail!("wrong PIN, or the connection is being relayed");
        }

        self.attempts.record_success(&peer_info.id.0);
        self.trust.confirm(
            peer_fingerprint,
            &peer_info.id.0,
            &peer_info.device_name,
            &peer_info.platform,
        )?;
        Ok(())
    }
}

/// Turn a device name into a valid mDNS instance name.
fn sanitize_instance_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "shunkan-android".to_string()
    } else {
        cleaned
    }
}

/// Pair two devices without a network exchange, for tests and for restoring a
/// backup. Prefer the PIN exchange for anything a user drives.
#[uniffi::export]
pub fn trust_peer_directly(
    data_dir: String,
    peer_id: String,
    device_name: String,
    platform: String,
    fingerprint: String,
) -> Result<(), ShunkanError> {
    let store =
        TrustStore::load_or_create(&PathBuf::from(data_dir)).map_err(ShunkanError::storage)?;
    store
        .pair(PairedPeer::new(peer_id, device_name, platform, fingerprint))
        .map_err(ShunkanError::pairing)
}

/// The library version, so the frontend can display and check it.
#[uniffi::export]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shunkan-ffi-{}-{}-{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[derive(Default)]
    struct Recorder {
        clipboard: Mutex<Vec<(String, String)>>,
        peer_changes: Mutex<u32>,
        errors: Mutex<Vec<String>>,
    }

    impl ShunkanListener for Recorder {
        fn on_clipboard_received(&self, text: String, source_peer: String) {
            self.clipboard.lock().unwrap().push((text, source_peer));
        }
        fn on_peers_changed(&self) {
            *self.peer_changes.lock().unwrap() += 1;
        }
        fn on_pairing_result(&self, _: String, _: bool, _: Option<String>) {}
        fn on_error(&self, message: String) {
            self.errors.lock().unwrap().push(message);
        }
    }

    #[test]
    fn test_engine_creates_and_persists_an_identity() {
        let dir = temp_dir("identity");
        let engine =
            ShunkanEngine::new(dir.to_string_lossy().to_string(), "Pixel 8".into()).unwrap();

        let peer_id = engine.peer_id();
        let fingerprint = engine.fingerprint();
        assert!(peer_id.starts_with("peer-"));
        assert_eq!(fingerprint.len(), 64);

        // A restart must be the same device.
        drop(engine);
        let again =
            ShunkanEngine::new(dir.to_string_lossy().to_string(), "Pixel 8".into()).unwrap();
        assert_eq!(again.peer_id(), peer_id);
        assert_eq!(again.fingerprint(), fingerprint);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_engine_reports_not_running_before_start() {
        let dir = temp_dir("notrunning");
        let engine = ShunkanEngine::new(dir.to_string_lossy().to_string(), "Pixel".into()).unwrap();

        assert!(!engine.is_running());
        assert!(matches!(
            engine.send_clipboard("hello".into()),
            Err(ShunkanError::NotRunning)
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_begin_pairing_validates_the_pin() {
        let dir = temp_dir("pin");
        let engine = ShunkanEngine::new(dir.to_string_lossy().to_string(), "Pixel".into()).unwrap();

        assert!(matches!(
            engine.begin_pairing("abc".into()),
            Err(ShunkanError::InvalidArgument { .. })
        ));
        assert!(engine.begin_pairing("123456".into()).is_ok());
        assert!(engine.trust.pairing_mode());

        engine.end_pairing();
        assert!(!engine.trust.pairing_mode());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_generated_pin_opens_the_pairing_window() {
        let dir = temp_dir("genpin");
        let engine = ShunkanEngine::new(dir.to_string_lossy().to_string(), "Pixel".into()).unwrap();

        let pin = engine.begin_pairing_with_generated_pin();
        assert_eq!(pin.len(), 6);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
        assert!(engine.trust.pairing_mode());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_history_surfaces_recorded_entries() {
        let dir = temp_dir("history");
        let engine = ShunkanEngine::new(dir.to_string_lossy().to_string(), "Pixel".into()).unwrap();

        engine.record(ClipboardItem::from_text("first", PeerId::new("p")));
        engine.record(ClipboardItem::from_text("second", PeerId::new("p")));

        let entries = engine.history(10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "second");
        assert_eq!(engine.history(1).len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_peers_reports_paired_devices_as_disconnected() {
        let dir = temp_dir("peers");
        let engine = ShunkanEngine::new(dir.to_string_lossy().to_string(), "Pixel".into()).unwrap();

        engine
            .trust
            .pair(PairedPeer::new("peer-x", "ThinkPad", "linux", "fp-x"))
            .unwrap();

        let peers = engine.peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer_id, "peer-x");
        assert!(peers[0].paired);
        assert!(!peers[0].connected);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_send_to_unknown_peer_is_an_error() {
        let dir = temp_dir("unknown");
        let engine = ShunkanEngine::new(dir.to_string_lossy().to_string(), "Pixel".into()).unwrap();
        engine.lock_state().running = true;

        assert!(matches!(
            engine.send_clipboard_to("ghost".into(), "hi".into()),
            Err(ShunkanError::UnknownPeer { .. })
        ));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_listener_receives_errors() {
        let dir = temp_dir("listener");
        let engine = ShunkanEngine::new(dir.to_string_lossy().to_string(), "Pixel".into()).unwrap();

        let recorder = Arc::new(Recorder::default());
        *engine.listener.lock().unwrap() = Some(recorder.clone());

        engine.report_error("something broke".into());
        engine.notify_peers_changed();

        assert_eq!(recorder.errors.lock().unwrap().len(), 1);
        assert_eq!(*recorder.peer_changes.lock().unwrap(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_trust_peer_directly_persists() {
        let dir = temp_dir("direct");
        let path = dir.to_string_lossy().to_string();

        trust_peer_directly(
            path.clone(),
            "peer-y".into(),
            "ThinkPad".into(),
            "linux".into(),
            "fp-y".into(),
        )
        .unwrap();

        let store = TrustStore::load_or_create(&dir).unwrap();
        assert!(store.is_trusted_fingerprint("fp-y"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_version_matches_the_crate() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_instance_name_sanitisation() {
        assert_eq!(sanitize_instance_name("Pixel 8 Pro"), "Pixel-8-Pro");
        assert_eq!(sanitize_instance_name("---"), "shunkan-android");
        assert_eq!(sanitize_instance_name(""), "shunkan-android");
    }
}

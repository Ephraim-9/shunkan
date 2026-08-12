//! Shared daemon state.
//!
//! Everything the daemon's three tasks — discovery, the QUIC listener, and the
//! clipboard monitor — need in common lives here behind one `Arc`. Before this
//! existed the tasks were `loop { sleep }` stubs that shared nothing, and the
//! IPC commands returned empty vectors because there was no state to read.

use crate::clipboard::{ClipboardMonitor, SessionType};
use shunkan_core::crypto::PairingPin;
use shunkan_core::history::ClipboardHistory;
use shunkan_core::identity::DeviceIdentity;
use shunkan_core::pairing::AttemptLimiter;
use shunkan_core::protocol::{ClipboardItem, Message, PeerId, PeerInfo};
use shunkan_core::trust::TrustStore;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

/// A change the UI should know about.
///
/// Deliberately coarse: the palette re-reads the relevant list when it sees one,
/// rather than trying to apply a diff. That keeps the event a *notification*
/// and the IPC commands the single source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiEvent {
    /// Clipboard history gained, lost, or reordered an entry.
    HistoryChanged,
    /// A peer connected or disconnected.
    PeersChanged,
}

impl UiEvent {
    /// The event name the frontend listens for.
    pub fn name(&self) -> &'static str {
        match self {
            UiEvent::HistoryChanged => "shunkan://history-changed",
            UiEvent::PeersChanged => "shunkan://peers-changed",
        }
    }
}

/// How many UI notifications may queue before the oldest are dropped.
///
/// Dropping is fine here: every event says "re-read", so a listener that missed
/// some still converges on the right state from the next one it sees.
const UI_EVENT_CAPACITY: usize = 32;

/// Something to send to a connected peer.
#[derive(Debug, Clone)]
pub enum Outbound {
    /// A clipboard item. The peer's writer task assigns the sequence number,
    /// so numbering stays monotonic per connection.
    Clipboard(Box<ClipboardItem>),
    /// Any other protocol message, sent as-is.
    Message(Box<Message>),
}

/// A live connection to a peer, as seen by the rest of the daemon.
#[derive(Debug, Clone)]
pub struct PeerHandle {
    /// The peer's advertised identity.
    pub info: PeerInfo,
    /// The address the connection is established over.
    pub addr: SocketAddr,
    /// The peer's pinned certificate fingerprint, when we authenticated it.
    pub fingerprint: Option<String>,
    /// When the connection was established (seconds since UNIX epoch).
    pub connected_at: u64,
    tx: mpsc::UnboundedSender<Outbound>,
}

impl PeerHandle {
    /// Create a handle around the writer task's channel.
    pub fn new(
        info: PeerInfo,
        addr: SocketAddr,
        fingerprint: Option<String>,
        tx: mpsc::UnboundedSender<Outbound>,
    ) -> Self {
        Self {
            info,
            addr,
            fingerprint,
            connected_at: now_secs(),
            tx,
        }
    }

    /// Queue something for delivery. Returns `false` if the peer has gone away.
    pub fn send(&self, outbound: Outbound) -> bool {
        self.tx.send(outbound).is_ok()
    }
}

/// State shared by every task in the daemon.
pub struct AppState {
    /// This device's persisted identity.
    pub identity: Arc<DeviceIdentity>,
    /// The paired-device trust store.
    pub trust: Arc<TrustStore>,
    /// This device's advertised identity.
    pub peer_info: PeerInfo,
    /// The detected display session type.
    pub session_type: SessionType,
    /// The port the QUIC listener is bound to.
    pub listening_port: u16,
    /// Rate limiter for PIN pairing attempts.
    pub pairing_attempts: AttemptLimiter,
    /// The PIN this device will pair with, when pairing mode is on.
    pairing_pin: Mutex<Option<PairingPin>>,
    /// Broadcast channel for UI refresh notifications.
    ///
    /// The palette used to poll `get_history` every two seconds, which is both
    /// wasteful and racy. State changes announce themselves here instead, and
    /// the Tauri layer forwards them to the webview as events. Kept as a plain
    /// broadcast channel so this module stays independent of Tauri.
    ui_events: broadcast::Sender<UiEvent>,
    /// Clipboard history, shared with the IPC commands.
    history: Mutex<ClipboardHistory>,
    /// Currently connected peers, keyed by peer ID.
    peers: Mutex<HashMap<PeerId, PeerHandle>>,
    /// The clipboard adapter, shared so peer tasks can write received content.
    clipboard: Arc<ClipboardMonitor>,
}

impl AppState {
    /// Assemble the daemon's shared state.
    pub fn new(
        identity: Arc<DeviceIdentity>,
        trust: Arc<TrustStore>,
        peer_info: PeerInfo,
        session_type: SessionType,
        listening_port: u16,
        clipboard: Arc<ClipboardMonitor>,
    ) -> Self {
        Self {
            identity,
            trust,
            peer_info,
            session_type,
            listening_port,
            history: Mutex::new(ClipboardHistory::with_default_capacity()),
            peers: Mutex::new(HashMap::new()),
            clipboard,
            pairing_attempts: AttemptLimiter::new(),
            pairing_pin: Mutex::new(None),
            ui_events: broadcast::channel(UI_EVENT_CAPACITY).0,
        }
    }

    /// Subscribe to UI refresh notifications.
    pub fn subscribe_ui(&self) -> broadcast::Receiver<UiEvent> {
        self.ui_events.subscribe()
    }

    /// Announce a change to any UI listeners. A no-op when nothing is listening.
    pub fn notify_ui(&self, event: UiEvent) {
        let _ = self.ui_events.send(event);
    }

    /// This device's peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_info.id
    }

    /// Arm pairing with the given PIN, or disarm it with `None`.
    pub fn set_pairing_pin(&self, pin: Option<PairingPin>) {
        let armed = pin.is_some();
        *self.pairing_pin.lock().unwrap_or_else(|e| e.into_inner()) = pin;
        self.trust.set_pairing_mode(armed);
    }

    /// The PIN currently armed for pairing, if any.
    pub fn pairing_pin(&self) -> Option<PairingPin> {
        self.pairing_pin
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The clipboard adapter.
    pub fn clipboard(&self) -> &Arc<ClipboardMonitor> {
        &self.clipboard
    }

    /// Record a clipboard item in history.
    ///
    /// Returns `true` if it was new, `false` if it deduplicated against an
    /// entry already present.
    pub fn record_clipboard(&self, item: ClipboardItem) -> bool {
        let added = self.lock_history().push(item);
        // Announce either way: a duplicate still moves to the front and
        // refreshes its timestamp, which the palette renders.
        self.notify_ui(UiEvent::HistoryChanged);
        added
    }

    /// Look up a history entry by its BLAKE3 content hash.
    pub fn history_entry(&self, hash: &str) -> Option<ClipboardItem> {
        self.lock_history().get_by_hash(hash).cloned()
    }

    /// Snapshot the most recent `limit` history entries, newest first.
    pub fn history_snapshot(&self, limit: usize) -> Vec<ClipboardItem> {
        self.lock_history().items().take(limit).cloned().collect()
    }

    /// Number of entries currently in history.
    pub fn history_len(&self) -> usize {
        self.lock_history().len()
    }

    /// Register a newly connected peer, replacing any previous handle for it.
    pub fn add_peer(&self, handle: PeerHandle) {
        let id = handle.info.id.clone();
        log::info!(
            "Peer connected: {} ({}) at {}",
            handle.info.device_name,
            id,
            handle.addr
        );
        self.lock_peers().insert(id, handle);
        self.notify_ui(UiEvent::PeersChanged);
    }

    /// Drop a peer that has disconnected.
    pub fn remove_peer(&self, id: &PeerId) {
        if self.lock_peers().remove(id).is_some() {
            log::info!("Peer disconnected: {}", id);
            self.notify_ui(UiEvent::PeersChanged);
        }
    }

    /// Whether we already hold a live connection to this peer.
    pub fn has_peer(&self, id: &PeerId) -> bool {
        self.lock_peers().contains_key(id)
    }

    /// Snapshot of currently connected peers.
    pub fn peers(&self) -> Vec<PeerHandle> {
        self.lock_peers().values().cloned().collect()
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.lock_peers().len()
    }

    /// Send a clipboard item to every connected peer.
    ///
    /// Returns the number of peers it was queued for. Peers whose writer task
    /// has exited are dropped as a side effect.
    pub fn broadcast_clipboard(&self, item: &ClipboardItem) -> usize {
        let mut dead = Vec::new();
        let mut delivered = 0;

        {
            let peers = self.lock_peers();
            for (id, handle) in peers.iter() {
                if handle.send(Outbound::Clipboard(Box::new(item.clone()))) {
                    delivered += 1;
                } else {
                    dead.push(id.clone());
                }
            }
        }

        if !dead.is_empty() {
            let mut peers = self.lock_peers();
            for id in dead {
                peers.remove(&id);
            }
        }

        delivered
    }

    /// Send a clipboard item to one peer. Returns `false` if it is not connected.
    pub fn send_to_peer(&self, peer_id: &PeerId, item: ClipboardItem) -> bool {
        let handle = self.lock_peers().get(peer_id).cloned();
        match handle {
            Some(handle) => handle.send(Outbound::Clipboard(Box::new(item))),
            None => false,
        }
    }

    fn lock_history(&self) -> std::sync::MutexGuard<'_, ClipboardHistory> {
        self.history.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_peers(&self) -> std::sync::MutexGuard<'_, HashMap<PeerId, PeerHandle>> {
        self.peers.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Current UNIX timestamp in seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shunkan_core::protocol::ContentType;

    fn test_state() -> Arc<AppState> {
        let identity = Arc::new(DeviceIdentity::generate().unwrap());
        let peer_info = PeerInfo::new(identity.peer_id().clone(), "TestBox", "linux");
        Arc::new(AppState::new(
            identity,
            Arc::new(TrustStore::in_memory()),
            peer_info,
            SessionType::X11,
            4433,
            Arc::new(ClipboardMonitor::with_session_type(SessionType::X11)),
        ))
    }

    fn handle(id: &str) -> (PeerHandle, mpsc::UnboundedReceiver<Outbound>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let info = PeerInfo::new(PeerId::new(id), format!("Device {}", id), "linux");
        (
            PeerHandle::new(info, "127.0.0.1:4433".parse().unwrap(), None, tx),
            rx,
        )
    }

    #[test]
    fn test_history_records_and_reads_back() {
        let state = test_state();
        let item = ClipboardItem::from_text("hello", PeerId::new("p1"));
        let hash = item.content_hash.clone();

        assert!(state.record_clipboard(item));
        assert_eq!(state.history_len(), 1);
        assert_eq!(state.history_entry(&hash).unwrap().data, b"hello");
        assert!(state.history_entry("nope").is_none());
    }

    #[test]
    fn test_history_deduplicates() {
        let state = test_state();
        assert!(state.record_clipboard(ClipboardItem::from_text("x", PeerId::new("p1"))));
        assert!(!state.record_clipboard(ClipboardItem::from_text("x", PeerId::new("p2"))));
        assert_eq!(state.history_len(), 1);
    }

    #[test]
    fn test_history_snapshot_is_newest_first_and_limited() {
        let state = test_state();
        for i in 0..5 {
            state.record_clipboard(ClipboardItem::from_text(
                format!("item-{}", i),
                PeerId::new("p"),
            ));
        }

        let snapshot = state.history_snapshot(3);
        assert_eq!(snapshot.len(), 3);
        assert_eq!(snapshot[0].data, b"item-4");
        assert_eq!(snapshot[2].data, b"item-2");
    }

    #[test]
    fn test_peer_registration_lifecycle() {
        let state = test_state();
        let (h, _rx) = handle("peer-1");
        let id = h.info.id.clone();

        assert_eq!(state.peer_count(), 0);
        state.add_peer(h);
        assert!(state.has_peer(&id));
        assert_eq!(state.peer_count(), 1);
        assert_eq!(state.peers()[0].info.device_name, "Device peer-1");

        state.remove_peer(&id);
        assert!(!state.has_peer(&id));
        assert_eq!(state.peer_count(), 0);
    }

    #[test]
    fn test_broadcast_reaches_every_connected_peer() {
        let state = test_state();
        let (h1, mut rx1) = handle("peer-1");
        let (h2, mut rx2) = handle("peer-2");
        state.add_peer(h1);
        state.add_peer(h2);

        let item = ClipboardItem::from_text("shared", PeerId::new("me"));
        assert_eq!(state.broadcast_clipboard(&item), 2);

        for rx in [&mut rx1, &mut rx2] {
            match rx.try_recv().unwrap() {
                Outbound::Clipboard(got) => assert_eq!(got.data, b"shared"),
                other => panic!("unexpected outbound: {:?}", other),
            }
        }
    }

    #[test]
    fn test_broadcast_prunes_peers_whose_task_has_exited() {
        let state = test_state();
        let (h1, rx1) = handle("peer-1");
        let (h2, mut rx2) = handle("peer-2");
        state.add_peer(h1);
        state.add_peer(h2);

        drop(rx1); // peer-1's writer task is gone

        let item = ClipboardItem::from_text("shared", PeerId::new("me"));
        assert_eq!(state.broadcast_clipboard(&item), 1);
        assert_eq!(state.peer_count(), 1);
        assert!(state.has_peer(&PeerId::new("peer-2")));
        assert!(rx2.try_recv().is_ok());
    }

    #[test]
    fn test_send_to_unknown_peer_fails() {
        let state = test_state();
        let item = ClipboardItem::from_text("x", PeerId::new("me"));
        assert!(!state.send_to_peer(&PeerId::new("ghost"), item));
    }

    #[test]
    fn test_send_to_peer_delivers() {
        let state = test_state();
        let (h, mut rx) = handle("peer-1");
        state.add_peer(h);

        let item = ClipboardItem::new(
            ContentType::PlainText,
            b"direct".to_vec(),
            PeerId::new("me"),
        );
        assert!(state.send_to_peer(&PeerId::new("peer-1"), item));
        assert!(matches!(rx.try_recv().unwrap(), Outbound::Clipboard(_)));
    }
}

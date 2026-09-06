//! IPC commands for the Shunkan desktop application.
//!
//! These functions will be registered as `#[tauri::command]` handlers when
//! Tauri v2 is fully integrated. They are the bridge API between the
//! glassmorphic command palette UI and the daemon's [`AppState`].
//!
//! # IPC Contract
//!
//! The frontend (app.js) invokes these by name; each returns a
//! JSON-serializable result.

use crate::clipboard::SessionType;
use crate::state::AppState;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use shunkan_core::protocol::{ClipboardItem, ContentType, PeerId, PeerInfo};

/// A simplified peer representation for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerView {
    /// Peer's unique identifier.
    pub id: String,
    /// Human-readable device name.
    pub device_name: String,
    /// Platform (linux, android).
    pub platform: String,
    /// Whether the peer is currently connected.
    pub connected: bool,
}

impl From<&PeerInfo> for PeerView {
    fn from(peer: &PeerInfo) -> Self {
        Self {
            id: peer.id.to_string(),
            device_name: peer.device_name.clone(),
            platform: peer.platform.clone(),
            connected: true,
        }
    }
}

/// A simplified clipboard history entry for the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// BLAKE3 content hash (used as unique key).
    pub hash: String,
    /// Content type label.
    pub content_type: String,
    /// Preview text (truncated to 200 chars for display).
    pub preview: String,
    /// Full text content (if text type).
    pub full_text: Option<String>,
    /// Timestamp (seconds since UNIX epoch).
    pub timestamp: u64,
    /// Source peer device name.
    pub source: String,
}

/// Maximum number of characters shown in a history preview.
///
/// Counted in **characters**, not bytes. Slicing `&text[..200]` by byte offset
/// panics the moment byte 200 lands mid-codepoint, which any paragraph of
/// Japanese, Cyrillic, or emoji does immediately.
const PREVIEW_CHARS: usize = 200;

/// Truncate to at most [`PREVIEW_CHARS`] characters, appending an ellipsis if
/// anything was cut.
fn preview_of(text: &str) -> String {
    match text.char_indices().nth(PREVIEW_CHARS) {
        Some((byte_idx, _)) => format!("{}…", &text[..byte_idx]),
        None => text.to_string(),
    }
}

impl From<&ClipboardItem> for HistoryEntry {
    fn from(item: &ClipboardItem) -> Self {
        let (content_type_label, preview, full_text) = match &item.content_type {
            ContentType::PlainText => {
                let text = String::from_utf8_lossy(&item.data).to_string();
                ("text".to_string(), preview_of(&text), Some(text))
            }
            ContentType::RichText => {
                let text = String::from_utf8_lossy(&item.data).to_string();
                ("rich_text".to_string(), preview_of(&text), Some(text))
            }
            ContentType::Image => (
                "image".to_string(),
                format!("[Image: {} bytes]", item.data.len()),
                None,
            ),
            ContentType::FileUri => {
                let uri = String::from_utf8_lossy(&item.data).to_string();
                ("file".to_string(), preview_of(&uri), Some(uri))
            }
        };

        Self {
            hash: item.content_hash.clone(),
            content_type: content_type_label,
            preview,
            full_text,
            timestamp: item.timestamp,
            source: item.source_peer.to_string(),
        }
    }
}

/// Tauri command handlers.
///
/// Thin wrappers so the logic below stays callable — and testable — without a
/// running Tauri app. The command *names* the frontend invokes come from these
/// function names, so they must match the names in `app.js`.
///
/// Tauri v2 converts camelCase arguments from JavaScript to snake_case
/// parameters here, so the frontend sends `{ peerId, text }`.
pub mod ipc {
    use super::*;
    use std::sync::Arc;
    use tauri::State;

    /// IPC: `invoke("get_peers")` → `PeerView[]`
    #[tauri::command]
    pub fn get_peers(state: State<'_, Arc<AppState>>) -> Vec<PeerView> {
        super::get_peers(&state)
    }

    /// IPC: `invoke("get_history", { limit })` → `HistoryEntry[]`
    #[tauri::command]
    pub fn get_history(state: State<'_, Arc<AppState>>, limit: Option<usize>) -> Vec<HistoryEntry> {
        super::get_history(&state, limit)
    }

    /// IPC: `invoke("send_to_peer", { peerId, text })` → `bool`
    #[tauri::command]
    pub fn send_to_peer(state: State<'_, Arc<AppState>>, peer_id: String, text: String) -> bool {
        super::send_to_peer(&state, &peer_id, text)
    }

    /// IPC: `invoke("paste_entry", { hash })` → `bool`
    #[tauri::command]
    pub fn paste_entry(state: State<'_, Arc<AppState>>, hash: String) -> bool {
        super::paste_entry(&state, &hash)
    }

    /// IPC: `invoke("get_status")` → `StatusInfo`
    #[tauri::command]
    pub fn get_status(state: State<'_, Arc<AppState>>) -> StatusInfo {
        super::get_status(&state)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// IPC Commands
//
// Each is backed by the daemon's shared `AppState`. The `ipc` module above wraps
// these for Tauri; these plain functions are what the tests drive.
// ──────────────────────────────────────────────────────────────────────────────

/// Get the list of connected peers on the local network.
///
/// IPC: `invoke("get_peers")` → `PeerView[]`
pub fn get_peers(state: &AppState) -> Vec<PeerView> {
    let peers: Vec<PeerView> = state
        .peers()
        .iter()
        .map(|handle| PeerView::from(&handle.info))
        .collect();
    debug!("IPC: get_peers → {} peer(s)", peers.len());
    peers
}

/// Get the clipboard history (most recent first).
///
/// IPC: `invoke("get_history", { limit })` → `HistoryEntry[]`
pub fn get_history(state: &AppState, limit: Option<usize>) -> Vec<HistoryEntry> {
    let limit = limit.unwrap_or(DEFAULT_HISTORY_LIMIT);
    let entries: Vec<HistoryEntry> = state
        .history_snapshot(limit)
        .iter()
        .map(HistoryEntry::from)
        .collect();
    debug!("IPC: get_history (limit={}) → {}", limit, entries.len());
    entries
}

/// Send clipboard text to a specific peer.
///
/// IPC: `invoke("send_to_peer", { peerId, text })` → `bool`
pub fn send_to_peer(state: &AppState, peer_id: &str, text: String) -> bool {
    let target = PeerId::new(peer_id);
    let item = ClipboardItem::from_text(text, state.peer_id().clone());
    let queued = state.send_to_peer(&target, item);

    if queued {
        info!("IPC: send_to_peer → queued for {}", peer_id);
    } else {
        warn!("IPC: send_to_peer → {} is not connected", peer_id);
    }
    queued
}

/// Paste a history entry to the system clipboard.
///
/// IPC: `invoke("paste_entry", { hash })` → `bool`
pub fn paste_entry(state: &AppState, hash: &str) -> bool {
    let Some(item) = state.history_entry(hash) else {
        warn!("IPC: paste_entry → no history entry {}", short(hash));
        return false;
    };

    let text = match item.content_type {
        ContentType::PlainText | ContentType::RichText | ContentType::FileUri => {
            match String::from_utf8(item.data) {
                Ok(text) => text,
                Err(e) => {
                    warn!(
                        "IPC: paste_entry → entry {} is not valid UTF-8: {}",
                        short(hash),
                        e
                    );
                    return false;
                }
            }
        }
        ContentType::Image => {
            warn!("IPC: paste_entry → image entries cannot be pasted as text yet");
            return false;
        }
    };

    match state.clipboard().write_to_clipboard(&text) {
        Ok(()) => {
            info!("IPC: paste_entry → wrote {} bytes to clipboard", text.len());
            true
        }
        Err(e) => {
            warn!("IPC: paste_entry → clipboard write failed: {}", e);
            false
        }
    }
}

/// Get the current connection status.
///
/// IPC: `invoke("get_status")` → `StatusInfo`
pub fn get_status(state: &AppState) -> StatusInfo {
    StatusInfo {
        peer_count: state.peer_count(),
        session_type: session_label(state.session_type),
        listening_port: state.listening_port,
        history_len: state.history_len(),
        paired_count: state.trust.len(),
        pairing_mode: state.trust.pairing_mode(),
        version: env!("CARGO_PKG_VERSION").into(),
    }
}

/// Default number of history entries returned by `get_history`.
const DEFAULT_HISTORY_LIMIT: usize = 50;

/// The wire label for a session type, matching what the frontend displays.
fn session_label(session_type: SessionType) -> String {
    match session_type {
        SessionType::X11 => "x11",
        SessionType::WaylandWlroots => "wayland-wlroots",
        SessionType::WaylandGnome => "wayland-gnome",
        SessionType::Unknown => "unknown",
    }
    .to_string()
}

/// Shorten a hash for logging without panicking on a short input.
fn short(hash: &str) -> &str {
    &hash[..8.min(hash.len())]
}

/// Status information returned by `get_status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    /// Number of connected peers.
    pub peer_count: usize,
    /// Detected session type (x11, wayland-wlroots, wayland-gnome, unknown).
    pub session_type: String,
    /// The QUIC listening port.
    pub listening_port: u16,
    /// Number of entries currently in clipboard history.
    pub history_len: usize,
    /// Number of devices this device has paired with.
    pub paired_count: usize,
    /// Whether trust-on-first-use pairing is currently enabled.
    pub pairing_mode: bool,
    /// Shunkan desktop version.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_view_from_peer_info() {
        let info = PeerInfo::new(PeerId::new("test-1"), "MyDevice", "linux");
        let view = PeerView::from(&info);
        assert_eq!(view.id, "test-1");
        assert_eq!(view.device_name, "MyDevice");
        assert_eq!(view.platform, "linux");
        assert!(view.connected);
    }

    #[test]
    fn test_history_entry_from_clipboard_item() {
        let item = ClipboardItem::from_text("hello world", PeerId::new("peer-1"));
        let entry = HistoryEntry::from(&item);
        assert_eq!(entry.content_type, "text");
        assert_eq!(entry.preview, "hello world");
        assert_eq!(entry.full_text, Some("hello world".to_string()));
        assert!(!entry.hash.is_empty());
    }

    #[test]
    fn test_history_entry_long_text_truncated() {
        let long_text = "a".repeat(500);
        let item = ClipboardItem::from_text(long_text.clone(), PeerId::new("peer-1"));
        let entry = HistoryEntry::from(&item);
        assert_eq!(entry.preview.chars().count(), PREVIEW_CHARS + 1); // + ellipsis
        assert_eq!(entry.full_text, Some(long_text));
    }

    /// The F-05 regression. `&text[..200]` panicked here: byte 200 of repeated
    /// U+65E5 (3 bytes each) is not a character boundary.
    #[test]
    fn test_history_entry_multibyte_text_does_not_panic() {
        for sample in ["日".repeat(300), "п".repeat(300), "🙂".repeat(300)] {
            let item = ClipboardItem::from_text(sample.clone(), PeerId::new("peer-1"));
            let entry = HistoryEntry::from(&item);

            assert_eq!(entry.preview.chars().count(), PREVIEW_CHARS + 1);
            assert!(entry.preview.ends_with('…'));
            assert_eq!(entry.full_text, Some(sample));
        }
    }

    #[test]
    fn test_preview_truncates_on_character_count_not_bytes() {
        // 250 three-byte characters: 750 bytes, but only 250 characters, so
        // exactly 200 survive.
        let text = "日".repeat(250);
        let preview = preview_of(&text);
        assert_eq!(preview.chars().count(), 201);
        assert_eq!(preview, format!("{}…", "日".repeat(200)));
    }

    #[test]
    fn test_preview_leaves_short_text_untouched() {
        assert_eq!(preview_of("short"), "short");
        assert_eq!(preview_of(""), "");
        // Exactly at the limit: nothing to cut, so no ellipsis.
        let exact = "x".repeat(PREVIEW_CHARS);
        assert_eq!(preview_of(&exact), exact);
    }

    #[test]
    fn test_file_uri_preview_is_also_truncated() {
        let long_uri = format!("file:///{}", "é".repeat(400));
        let item = ClipboardItem::new(
            ContentType::FileUri,
            long_uri.clone().into_bytes(),
            PeerId::new("peer-1"),
        );
        let entry = HistoryEntry::from(&item);

        assert_eq!(entry.preview.chars().count(), PREVIEW_CHARS + 1);
        assert_eq!(entry.full_text, Some(long_uri));
    }

    // ── State-backed command tests ───────────────────────────────────────────

    use crate::clipboard::ClipboardMonitor;
    use shunkan_core::identity::DeviceIdentity;
    use shunkan_core::trust::TrustStore;
    use std::sync::Arc;

    fn test_state() -> Arc<AppState> {
        let identity = Arc::new(DeviceIdentity::generate().unwrap());
        let peer_info = PeerInfo::new(identity.peer_id().clone(), "TestBox", "linux");
        Arc::new(AppState::new(
            identity,
            Arc::new(TrustStore::in_memory()),
            peer_info,
            SessionType::WaylandWlroots,
            4433,
            Arc::new(ClipboardMonitor::with_session_type(SessionType::X11)),
        ))
    }

    #[test]
    fn test_get_history_reflects_recorded_items() {
        let state = test_state();
        assert!(get_history(&state, None).is_empty());

        state.record_clipboard(ClipboardItem::from_text("first", PeerId::new("p")));
        state.record_clipboard(ClipboardItem::from_text("second", PeerId::new("p")));

        let entries = get_history(&state, None);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].preview, "second");
        assert_eq!(entries[1].preview, "first");
    }

    #[test]
    fn test_get_history_honours_limit() {
        let state = test_state();
        for i in 0..10 {
            state.record_clipboard(ClipboardItem::from_text(
                format!("i{}", i),
                PeerId::new("p"),
            ));
        }
        assert_eq!(get_history(&state, Some(3)).len(), 3);
    }

    #[test]
    fn test_get_status_reports_live_state() {
        let state = test_state();
        state.record_clipboard(ClipboardItem::from_text("x", PeerId::new("p")));

        let status = get_status(&state);
        assert_eq!(status.session_type, "wayland-wlroots");
        assert_eq!(status.listening_port, 4433);
        assert_eq!(status.history_len, 1);
        assert_eq!(status.peer_count, 0);
        assert_eq!(status.paired_count, 0);
        assert!(!status.pairing_mode);
        assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_get_peers_is_empty_without_connections() {
        assert!(get_peers(&test_state()).is_empty());
    }

    #[test]
    fn test_send_to_unknown_peer_returns_false() {
        let state = test_state();
        assert!(!send_to_peer(&state, "nobody", "hello".into()));
    }

    #[test]
    fn test_paste_unknown_entry_returns_false() {
        let state = test_state();
        assert!(!paste_entry(&state, "not-a-hash"));
        // Short hashes must not panic the logging path.
        assert!(!paste_entry(&state, "ab"));
        assert!(!paste_entry(&state, ""));
    }

    #[test]
    fn test_paste_image_entry_is_refused() {
        let state = test_state();
        let item = ClipboardItem::new(ContentType::Image, vec![0x89, 0x50], PeerId::new("p"));
        let hash = item.content_hash.clone();
        state.record_clipboard(item);

        assert!(!paste_entry(&state, &hash));
    }

    #[test]
    fn test_session_label_covers_every_variant() {
        assert_eq!(session_label(SessionType::X11), "x11");
        assert_eq!(
            session_label(SessionType::WaylandWlroots),
            "wayland-wlroots"
        );
        assert_eq!(session_label(SessionType::WaylandGnome), "wayland-gnome");
        assert_eq!(session_label(SessionType::Unknown), "unknown");
    }
}

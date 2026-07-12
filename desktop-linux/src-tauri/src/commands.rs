//! Tauri IPC command stubs for the Shunkan desktop application.
//!
//! These functions will be registered as `#[tauri::command]` handlers when
//! Tauri v2 is fully integrated. For now, they serve as the bridge API
//! between the glassmorphic command palette UI and `shunkan-core`.
//!
//! # IPC Contract
//!
//! The frontend (app.js) invokes these via `window.__TAURI__.invoke("command_name", { args })`.
//! Each command returns a JSON-serializable result.

use log::{debug, info};
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

impl From<&ClipboardItem> for HistoryEntry {
    fn from(item: &ClipboardItem) -> Self {
        let (content_type_label, preview, full_text) = match &item.content_type {
            ContentType::PlainText => {
                let text = String::from_utf8_lossy(&item.data).to_string();
                let preview = if text.len() > 200 {
                    format!("{}…", &text[..200])
                } else {
                    text.clone()
                };
                ("text".to_string(), preview, Some(text))
            }
            ContentType::RichText => {
                let text = String::from_utf8_lossy(&item.data).to_string();
                let preview = if text.len() > 200 {
                    format!("{}…", &text[..200])
                } else {
                    text.clone()
                };
                ("rich_text".to_string(), preview, Some(text))
            }
            ContentType::Image => (
                "image".to_string(),
                format!("[Image: {} bytes]", item.data.len()),
                None,
            ),
            ContentType::FileUri => {
                let uri = String::from_utf8_lossy(&item.data).to_string();
                ("file".to_string(), uri.clone(), Some(uri))
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

// ──────────────────────────────────────────────────────────────────────────────
// Tauri IPC Command Stubs
//
// When Tauri is integrated, annotate each with `#[tauri::command]`.
// For now, these are plain async functions matching the expected IPC contract.
// ──────────────────────────────────────────────────────────────────────────────

/// Get the list of discovered peers on the local network.
///
/// IPC: `invoke("get_peers")` → `PeerView[]`
pub async fn get_peers() -> Vec<PeerView> {
    info!("IPC: get_peers");
    // TODO: Wire to shunkan_core::discovery when available
    vec![]
}

/// Get the clipboard history (most recent first).
///
/// IPC: `invoke("get_history", { limit })` → `HistoryEntry[]`
pub async fn get_history(limit: Option<usize>) -> Vec<HistoryEntry> {
    let limit = limit.unwrap_or(50);
    info!("IPC: get_history (limit={})", limit);
    // TODO: Wire to shunkan_core::history when available
    vec![]
}

/// Send clipboard text to a specific peer.
///
/// IPC: `invoke("send_to_peer", { peer_id, text })` → `bool`
pub async fn send_to_peer(peer_id: String, text: String) -> bool {
    info!(
        "IPC: send_to_peer (peer={}, {} bytes)",
        peer_id,
        text.len()
    );
    // TODO: Wire to shunkan_core::transport when available
    debug!("Would send to peer {}: {} bytes", peer_id, text.len());
    false
}

/// Paste a history entry to the system clipboard.
///
/// IPC: `invoke("paste_entry", { hash })` → `bool`
pub async fn paste_entry(hash: String) -> bool {
    info!("IPC: paste_entry (hash={})", &hash[..8.min(hash.len())]);
    // TODO: Look up entry from history by hash and write to clipboard
    false
}

/// Get the current connection status.
///
/// IPC: `invoke("get_status")` → `StatusInfo`
pub async fn get_status() -> StatusInfo {
    info!("IPC: get_status");
    StatusInfo {
        peer_count: 0,
        session_type: "unknown".into(),
        listening_port: shunkan_core::DEFAULT_PORT,
        version: env!("CARGO_PKG_VERSION").into(),
    }
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
        assert!(entry.preview.len() < 210); // 200 + "…"
        assert_eq!(entry.full_text, Some(long_text));
    }
}

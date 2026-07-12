//! Clipboard adapter for Linux desktop with session-type detection.
//!
//! Implements the tiered clipboard strategy from ADR-004:
//! - X11: uses `arboard` for clipboard monitoring
//! - Wayland (wlroots): `arboard` as fallback (ext-data-control-v1 planned)
//! - GNOME Wayland: `arboard` fallback + toast notification for paste
//!
//! Includes BLAKE3 hash-based deduplication to prevent feedback loops
//! (see memory.html: "X11 Clipboard Feedback Loop Deadlock" edge case).

use anyhow::{Context, Result};
use arboard::Clipboard;
use log::{debug, info, trace, warn};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The detected display session type for clipboard strategy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    /// X11 session — full arboard support + enigo injection.
    X11,
    /// Wayland session (wlroots compositors: Hyprland, Sway, KDE).
    /// Supports ext-data-control-v1 via wl-clipboard-rs + wtype injection.
    WaylandWlroots,
    /// GNOME Wayland session — clipboard write fallback + toast for paste.
    WaylandGnome,
    /// Unknown session type — fallback to arboard polling.
    Unknown,
}

impl SessionType {
    /// Detect the current session type from environment variables.
    ///
    /// Checks `$XDG_SESSION_TYPE` first, then inspects `$XDG_CURRENT_DESKTOP`
    /// and `$WAYLAND_DISPLAY` to disambiguate Wayland compositors.
    pub fn detect() -> Self {
        let session_type = std::env::var("XDG_SESSION_TYPE").unwrap_or_default();
        let current_desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        let wayland_display = std::env::var("WAYLAND_DISPLAY").ok();

        match session_type.to_lowercase().as_str() {
            "x11" => {
                info!("Detected X11 session");
                SessionType::X11
            }
            "wayland" => {
                let desktop_lower = current_desktop.to_lowercase();
                if desktop_lower.contains("gnome") || desktop_lower.contains("ubuntu") {
                    info!(
                        "Detected GNOME Wayland session (XDG_CURRENT_DESKTOP={})",
                        current_desktop
                    );
                    SessionType::WaylandGnome
                } else {
                    info!(
                        "Detected wlroots-compatible Wayland session (XDG_CURRENT_DESKTOP={})",
                        current_desktop
                    );
                    SessionType::WaylandWlroots
                }
            }
            _ => {
                // Fallback: check if WAYLAND_DISPLAY is set even without XDG_SESSION_TYPE
                if wayland_display.is_some() {
                    info!("XDG_SESSION_TYPE not set but WAYLAND_DISPLAY present — assuming Wayland");
                    let desktop_lower = current_desktop.to_lowercase();
                    if desktop_lower.contains("gnome") {
                        SessionType::WaylandGnome
                    } else {
                        SessionType::WaylandWlroots
                    }
                } else {
                    warn!("Could not detect session type — falling back to arboard polling");
                    SessionType::Unknown
                }
            }
        }
    }

    /// Returns a human-readable label for logging.
    pub fn label(&self) -> &'static str {
        match self {
            SessionType::X11 => "X11",
            SessionType::WaylandWlroots => "Wayland (wlroots)",
            SessionType::WaylandGnome => "Wayland (GNOME)",
            SessionType::Unknown => "Unknown",
        }
    }
}

/// Clipboard monitor that polls for changes and deduplicates via BLAKE3 hashing.
///
/// The dedup mechanism prevents the feedback loop described in memory.html:
/// when shunkan-core writes remote text into the local clipboard, arboard
/// re-triggers a "copy" event. By comparing BLAKE3 hashes, we skip re-broadcasting
/// content that we ourselves just wrote.
pub struct ClipboardMonitor {
    /// The detected session type.
    session_type: SessionType,
    /// BLAKE3 hash of the last clipboard content we read (for dedup).
    last_hash: Arc<Mutex<Option<String>>>,
    /// BLAKE3 hash of content we recently wrote TO the clipboard (feedback loop guard).
    last_written_hash: Arc<Mutex<Option<String>>>,
    /// Polling interval for clipboard checks.
    poll_interval: Duration,
}

impl ClipboardMonitor {
    /// Create a new clipboard monitor with automatic session detection.
    pub fn new() -> Self {
        Self::with_session_type(SessionType::detect())
    }

    /// Create a clipboard monitor with an explicit session type (useful for testing).
    pub fn with_session_type(session_type: SessionType) -> Self {
        info!(
            "Initializing clipboard monitor for {} session",
            session_type.label()
        );
        Self {
            session_type,
            last_hash: Arc::new(Mutex::new(None)),
            last_written_hash: Arc::new(Mutex::new(None)),
            poll_interval: Duration::from_millis(500),
        }
    }

    /// Get the detected session type.
    pub fn session_type(&self) -> SessionType {
        self.session_type
    }

    /// Compute BLAKE3 hash of clipboard content for dedup.
    fn hash_content(content: &str) -> String {
        blake3::hash(content.as_bytes()).to_hex().to_string()
    }

    /// Check if the clipboard has new content that we didn't write ourselves.
    ///
    /// Returns `Some(text)` if the clipboard contains new text that:
    /// 1. Is different from the last text we read (hash-based dedup)
    /// 2. Was NOT written by us (feedback loop prevention)
    ///
    /// Returns `None` if the clipboard hasn't changed or contains our own content.
    pub fn poll_for_changes(&self) -> Result<Option<String>> {
        let mut clipboard =
            Clipboard::new().context("Failed to initialize arboard clipboard")?;

        let text = match clipboard.get_text() {
            Ok(t) => t,
            Err(arboard::Error::ContentNotAvailable) => {
                trace!("Clipboard has no text content");
                return Ok(None);
            }
            Err(e) => {
                debug!("Clipboard read error: {}", e);
                return Ok(None);
            }
        };

        if text.is_empty() {
            return Ok(None);
        }

        let hash = Self::hash_content(&text);

        // Check if this content was written by us (feedback loop guard).
        {
            let written_hash = self.last_written_hash.lock().unwrap();
            if written_hash.as_deref() == Some(&hash) {
                trace!("Skipping clipboard content — matches our last write (feedback loop prevention)");
                return Ok(None);
            }
        }

        // Check if this is actually new content.
        {
            let mut last_hash = self.last_hash.lock().unwrap();
            if last_hash.as_deref() == Some(&hash) {
                trace!("Clipboard unchanged (hash match)");
                return Ok(None);
            }
            *last_hash = Some(hash);
        }

        debug!("New clipboard content detected ({} bytes)", text.len());
        Ok(Some(text))
    }

    /// Write text to the clipboard and record its hash to prevent feedback loops.
    ///
    /// After writing, the next `poll_for_changes` call will skip this content
    /// since we recognize it as our own write via the BLAKE3 hash nonce.
    pub fn write_to_clipboard(&self, text: &str) -> Result<()> {
        let mut clipboard =
            Clipboard::new().context("Failed to initialize arboard clipboard")?;

        let hash = Self::hash_content(text);

        // Record the hash BEFORE writing to prevent race conditions.
        {
            let mut written_hash = self.last_written_hash.lock().unwrap();
            *written_hash = Some(hash.clone());
        }

        // Also update last_hash so we don't detect our own write as "new".
        {
            let mut last_hash = self.last_hash.lock().unwrap();
            *last_hash = Some(hash);
        }

        clipboard
            .set_text(text)
            .context("Failed to write text to clipboard")?;

        debug!("Wrote {} bytes to clipboard", text.len());
        Ok(())
    }

    /// Get the polling interval for clipboard monitoring.
    pub fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Run the clipboard monitoring loop (blocking).
    ///
    /// Calls the provided callback whenever new clipboard content is detected.
    /// This is a stub implementation using arboard polling — future versions
    /// will use native Wayland protocols for event-driven monitoring.
    pub async fn run_monitor_loop<F>(&self, on_change: F) -> Result<()>
    where
        F: Fn(String) + Send + 'static,
    {
        info!(
            "Starting clipboard monitor loop ({}, interval={:?})",
            self.session_type.label(),
            self.poll_interval
        );

        loop {
            match self.poll_for_changes() {
                Ok(Some(text)) => {
                    info!("Clipboard change detected, broadcasting...");
                    on_change(text);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!("Clipboard poll error: {}", e);
                }
            }

            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_type_label() {
        assert_eq!(SessionType::X11.label(), "X11");
        assert_eq!(SessionType::WaylandWlroots.label(), "Wayland (wlroots)");
        assert_eq!(SessionType::WaylandGnome.label(), "Wayland (GNOME)");
        assert_eq!(SessionType::Unknown.label(), "Unknown");
    }

    #[test]
    fn test_hash_content_deterministic() {
        let h1 = ClipboardMonitor::hash_content("hello world");
        let h2 = ClipboardMonitor::hash_content("hello world");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // BLAKE3 hex = 64 chars
    }

    #[test]
    fn test_hash_content_different() {
        let h1 = ClipboardMonitor::hash_content("hello");
        let h2 = ClipboardMonitor::hash_content("world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_clipboard_monitor_creation() {
        let monitor = ClipboardMonitor::with_session_type(SessionType::X11);
        assert_eq!(monitor.session_type(), SessionType::X11);
        assert_eq!(monitor.poll_interval(), Duration::from_millis(500));
    }
}

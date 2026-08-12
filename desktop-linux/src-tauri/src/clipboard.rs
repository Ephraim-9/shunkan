//! Clipboard adapter for Linux desktop with session-type detection.
//!
//! Implements the tiered clipboard strategy from ADR-004:
//! - X11: uses `arboard` for clipboard monitoring
//! - Wayland (wlroots): `arboard` as fallback (ext-data-control-v1 planned)
//! - GNOME Wayland: `arboard` fallback + toast notification for paste
//!
//! Includes BLAKE3 hash-based deduplication to prevent feedback loops
//! (see memory.html: "X11 Clipboard Feedback Loop Deadlock" edge case).
//!
//! ## Clipboard ownership
//!
//! On X11 and Wayland the clipboard is a live ownership protocol, not a store:
//! whoever last copied is expected to serve requests for the content, and when
//! that process (or, for arboard, that connection) goes away the content goes
//! with it. arboard says so itself when a `Clipboard` is dropped shortly after
//! a write:
//!
//! > Clipboard was dropped very quickly after writing; clipboard managers may
//! > not have seen the contents. Consider keeping `Clipboard` in more
//! > persistent state somewhere […]
//!
//! So [`ClipboardBackend`] holds **one** connection for the process lifetime.
//! That fixes two things at once: written content survives, and polling stops
//! opening a fresh display-server connection twenty times a minute.
//!
//! On X11 a write additionally goes through a short-lived owner thread using
//! `SetExtLinux::wait()`, which keeps serving selection requests until another
//! application takes ownership.

use anyhow::{Context, Result};
use arboard::Clipboard;
use log::{debug, error, info, trace, warn};
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
                    info!(
                        "XDG_SESSION_TYPE not set but WAYLAND_DISPLAY present — assuming Wayland"
                    );
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

/// A single, long-lived connection to the display server's clipboard.
///
/// Created lazily on first use so that constructing a [`ClipboardMonitor`] in a
/// headless environment (CI, a unit test) does not fail. Once created it is
/// kept for the process lifetime; see the module docs for why that matters.
struct ClipboardBackend {
    session_type: SessionType,
    handle: Mutex<Option<Clipboard>>,
}

impl ClipboardBackend {
    fn new(session_type: SessionType) -> Self {
        Self {
            session_type,
            handle: Mutex::new(None),
        }
    }

    /// Run `op` against the persistent clipboard connection, opening it first
    /// if this is the first use.
    fn with_handle<T>(&self, op: impl FnOnce(&mut Clipboard) -> Result<T>) -> Result<T> {
        let mut guard = self.handle.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            let clipboard =
                Clipboard::new().context("Failed to open a connection to the system clipboard")?;
            debug!("Opened persistent clipboard connection");
            *guard = Some(clipboard);
        }
        op(guard.as_mut().expect("clipboard was just opened"))
    }

    /// Drop the persistent connection so the next use reopens it.
    ///
    /// The monitor calls this after repeated failures — a display server that
    /// restarted leaves the old connection permanently broken, and reopening is
    /// the only recovery.
    fn reset(&self) {
        let mut guard = self.handle.lock().unwrap_or_else(|e| e.into_inner());
        if guard.take().is_some() {
            warn!("Dropped the clipboard connection; it will be reopened on next use");
        }
    }

    /// Read the clipboard's text.
    ///
    /// `Ok(None)` means "there is no text on the clipboard right now" — an
    /// ordinary, expected state. Every other failure is an `Err`, so a broken
    /// display connection is distinguishable from an idle clipboard.
    fn read_text(&self) -> Result<Option<String>> {
        self.with_handle(|clipboard| match clipboard.get_text() {
            Ok(text) => Ok(Some(text)),
            Err(arboard::Error::ContentNotAvailable) => {
                trace!("Clipboard has no text content");
                Ok(None)
            }
            Err(arboard::Error::ClipboardNotSupported) => {
                Err(anyhow::anyhow!("This platform has no supported clipboard"))
            }
            Err(e) => Err(anyhow::Error::new(e).context("Failed to read the clipboard")),
        })
    }

    /// Write text to the clipboard.
    fn write_text(&self, text: &str) -> Result<()> {
        match self.session_type {
            SessionType::X11 => self.write_text_x11(text),
            _ => self.with_handle(|clipboard| {
                clipboard
                    .set_text(text)
                    .context("Failed to write text to the clipboard")
            }),
        }
    }

    /// Write on X11 via a dedicated owner thread that keeps serving requests.
    ///
    /// `SetExtLinux::wait()` blocks until another application takes ownership,
    /// so it cannot run on the caller's thread — and it cannot run on a single
    /// shared owner thread either, since that thread would be blocked when the
    /// next write arrives. One thread per write is the shape that works: the
    /// previous owner unblocks as soon as this one takes the selection, so at
    /// most a couple are ever alive.
    ///
    /// The thread reports back once it has a clipboard connection. arboard sets
    /// the data before it starts waiting, so by the time this returns the
    /// content is on the clipboard; a later failure while serving requests can
    /// only be logged.
    fn write_text_x11(&self, text: &str) -> Result<()> {
        use arboard::SetExtLinux;

        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();
        let owned_text = text.to_string();

        std::thread::Builder::new()
            .name("shunkan-clipboard-owner".to_string())
            .spawn(move || {
                let mut clipboard = match Clipboard::new() {
                    Ok(clipboard) => clipboard,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow::Error::new(e)
                            .context("Clipboard owner thread could not open a connection")));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));

                // Sets the selection, then serves requests until another
                // application copies something.
                if let Err(e) = clipboard.set().wait().text(owned_text) {
                    error!("Clipboard owner thread stopped serving: {}", e);
                }
                trace!("Clipboard ownership handed over");
            })
            .context("Failed to spawn the clipboard owner thread")?;

        ready_rx
            .recv_timeout(OWNER_THREAD_READY_TIMEOUT)
            .context("Clipboard owner thread did not start in time")?
    }
}

/// How long to wait for the X11 owner thread to acquire a clipboard connection.
const OWNER_THREAD_READY_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// BLAKE3 hash of content we wrote to the clipboard, consumed the first
    /// time it suppresses a poll (feedback loop guard).
    last_written_hash: Arc<Mutex<Option<String>>>,
    /// Polling interval for clipboard checks.
    poll_interval: Duration,
    /// The persistent display-server connection.
    backend: ClipboardBackend,
}

impl Default for ClipboardMonitor {
    fn default() -> Self {
        Self::new()
    }
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
            backend: ClipboardBackend::new(session_type),
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
    /// Returns `Ok(None)` if the clipboard hasn't changed, is empty, holds no
    /// text, or holds content we just wrote. Returns `Err` for a genuine
    /// failure — a broken display connection must not look like an idle
    /// clipboard, or the monitor loop spins forever with nothing to report.
    pub fn poll_for_changes(&self) -> Result<Option<String>> {
        let Some(text) = self.backend.read_text()? else {
            return Ok(None);
        };

        if text.is_empty() {
            return Ok(None);
        }

        let hash = Self::hash_content(&text);

        if self.consume_write_guard(&hash) {
            trace!(
                "Skipping clipboard content — matches our last write (feedback loop prevention)"
            );
            return Ok(None);
        }

        // Check if this is actually new content.
        {
            let mut last_hash = self.lock_last_hash();
            if last_hash.as_deref() == Some(&hash) {
                trace!("Clipboard unchanged (hash match)");
                return Ok(None);
            }
            *last_hash = Some(hash);
        }

        debug!("New clipboard content detected ({} bytes)", text.len());
        Ok(Some(text))
    }

    /// Check the feedback-loop guard against `hash`, clearing it on a match.
    ///
    /// The guard is deliberately **one-shot**. It used to be set on write and
    /// never cleared, which meant a user who received a password from their
    /// phone could never deliberately re-copy that same text again — the value
    /// was suppressed forever. Clearing on first use suppresses exactly the one
    /// echo the write provokes, and nothing after it.
    fn consume_write_guard(&self, hash: &str) -> bool {
        let mut written_hash = self.lock_written_hash();
        if written_hash.as_deref() == Some(hash) {
            *written_hash = None;
            true
        } else {
            false
        }
    }

    /// Write text to the clipboard and record its hash to prevent feedback loops.
    ///
    /// After writing, the next `poll_for_changes` call will skip this content
    /// once, since we recognize it as our own write via the BLAKE3 hash nonce.
    pub fn write_to_clipboard(&self, text: &str) -> Result<()> {
        let hash = Self::hash_content(text);

        // Record the hash BEFORE writing to prevent race conditions.
        *self.lock_written_hash() = Some(hash.clone());
        // Also update last_hash so we don't detect our own write as "new".
        *self.lock_last_hash() = Some(hash);

        if let Err(e) = self.backend.write_text(text) {
            // The write failed, so no echo is coming; leaving the guard armed
            // would suppress the user's next deliberate copy of this text.
            *self.lock_written_hash() = None;
            return Err(e);
        }

        debug!("Wrote {} bytes to clipboard", text.len());
        Ok(())
    }

    fn lock_last_hash(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.last_hash.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_written_hash(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.last_written_hash
            .lock()
            .unwrap_or_else(|e| e.into_inner())
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
    ///
    /// Consecutive read failures back off exponentially rather than spinning at
    /// the poll interval, and after [`FAILURES_BEFORE_RESET`] the display
    /// connection is dropped and reopened — the only recovery from a compositor
    /// that restarted underneath us.
    pub async fn run_monitor_loop<F>(&self, on_change: F) -> Result<()>
    where
        F: Fn(String) + Send + 'static,
    {
        info!(
            "Starting clipboard monitor loop ({}, interval={:?})",
            self.session_type.label(),
            self.poll_interval
        );

        let mut consecutive_failures: u32 = 0;

        loop {
            match self.poll_for_changes() {
                Ok(Some(text)) => {
                    consecutive_failures = 0;
                    info!("Clipboard change detected, broadcasting...");
                    on_change(text);
                }
                Ok(None) => {
                    consecutive_failures = 0;
                }
                Err(e) => {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    warn!(
                        "Clipboard poll error (failure {}): {:#}",
                        consecutive_failures, e
                    );

                    if consecutive_failures.is_multiple_of(FAILURES_BEFORE_RESET) {
                        self.backend.reset();
                    }

                    let backoff = self.backoff_for(consecutive_failures);
                    debug!("Backing off {:?} before the next clipboard poll", backoff);
                    tokio::time::sleep(backoff).await;
                    continue;
                }
            }

            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// Exponential backoff for `failures` consecutive read errors, capped at
    /// [`MAX_POLL_BACKOFF`].
    fn backoff_for(&self, failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(MAX_BACKOFF_SHIFT);
        let scaled = self
            .poll_interval
            .saturating_mul(1u32 << shift)
            .min(MAX_POLL_BACKOFF);
        scaled.max(self.poll_interval)
    }
}

/// Reopen the display connection after this many consecutive read failures.
const FAILURES_BEFORE_RESET: u32 = 5;

/// Ceiling on the poll backoff after repeated failures.
const MAX_POLL_BACKOFF: Duration = Duration::from_secs(30);

/// Largest exponent applied to the poll interval, so the shift cannot overflow.
const MAX_BACKOFF_SHIFT: u32 = 8;

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

    /// The F-07 regression. The guard used to be set on write and never
    /// cleared, so the guarded text could never be copied deliberately again.
    #[test]
    fn test_write_guard_is_one_shot() {
        let monitor = ClipboardMonitor::with_session_type(SessionType::X11);
        let hash = ClipboardMonitor::hash_content("hunter2");

        *monitor.lock_written_hash() = Some(hash.clone());

        // The echo our own write provokes is suppressed once…
        assert!(monitor.consume_write_guard(&hash));
        // …and the user's next deliberate copy of the same text is not.
        assert!(!monitor.consume_write_guard(&hash));
        assert!(monitor.lock_written_hash().is_none());
    }

    #[test]
    fn test_write_guard_ignores_other_content() {
        let monitor = ClipboardMonitor::with_session_type(SessionType::X11);
        *monitor.lock_written_hash() = Some(ClipboardMonitor::hash_content("ours"));

        assert!(!monitor.consume_write_guard(&ClipboardMonitor::hash_content("theirs")));
        // A non-matching poll must not disarm the guard.
        assert!(monitor.lock_written_hash().is_some());
    }

    #[test]
    fn test_backoff_grows_and_is_capped() {
        let monitor = ClipboardMonitor::with_session_type(SessionType::X11);
        let interval = monitor.poll_interval();

        assert_eq!(monitor.backoff_for(0), interval);
        assert_eq!(monitor.backoff_for(1), interval);
        assert_eq!(monitor.backoff_for(2), interval * 2);
        assert_eq!(monitor.backoff_for(3), interval * 4);

        // Never below the poll interval, never above the ceiling, never
        // overflowing however many failures accumulate.
        for failures in [10u32, 100, 10_000, u32::MAX] {
            let backoff = monitor.backoff_for(failures);
            assert!(backoff >= interval);
            assert!(backoff <= MAX_POLL_BACKOFF);
        }
    }

    #[test]
    fn test_backend_reset_is_safe_when_never_opened() {
        // No display server in CI, so the connection was never established;
        // resetting must not panic.
        let monitor = ClipboardMonitor::with_session_type(SessionType::Unknown);
        monitor.backend.reset();
        monitor.backend.reset();
    }

    /// Without a display server every read fails. The point of F-11 is that
    /// this surfaces as `Err`, not as `Ok(None)` masquerading as an idle
    /// clipboard. Skipped when a real display is present.
    #[test]
    fn test_read_failure_is_not_reported_as_idle() {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return;
        }

        let monitor = ClipboardMonitor::with_session_type(SessionType::Unknown);
        assert!(
            monitor.poll_for_changes().is_err(),
            "a broken clipboard connection must be distinguishable from an empty clipboard"
        );
    }

    /// A failed write must not leave the feedback guard armed, or the user's
    /// next deliberate copy of that text would be swallowed.
    #[test]
    fn test_failed_write_disarms_the_guard() {
        if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return;
        }

        let monitor = ClipboardMonitor::with_session_type(SessionType::Unknown);
        assert!(monitor.write_to_clipboard("secret").is_err());
        assert!(monitor.lock_written_hash().is_none());
    }
}

//! Shunkan Desktop Linux — CLI daemon entry point.
//!
//! This binary serves as the headless daemon for the Shunkan P2P clipboard
//! sync engine on Linux. It will eventually be wrapped by Tauri v2 for the
//! system tray UI, but runs standalone for development and testing.
//!
//! ## What it does
//!
//! 1. Initializes logging (via `RUST_LOG` env var)
//! 2. Detects the display session type (X11 / Wayland / GNOME)
//! 3. Starts mDNS-SD discovery for `_shunkan-sync._udp.local.`
//! 4. Starts the QUIC transport listener on port 4433/udp
//! 5. Monitors clipboard changes with hash-based dedup
//! 6. Prints discovered peers to stdout

mod clipboard;
mod commands;

use anyhow::Result;
use clipboard::{ClipboardMonitor, SessionType};
use log::{error, info, warn};
use shunkan_core::protocol::{PeerId, PeerInfo};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging — defaults to info level if RUST_LOG not set.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    info!("╔══════════════════════════════════════════════╗");
    info!("║  Shunkan P2P Engine — Desktop Linux Daemon   ║");
    info!("║  瞬間 (Shunkan) v{}                    ║", env!("CARGO_PKG_VERSION"));
    info!("╚══════════════════════════════════════════════╝");

    // Generate a peer identity for this session.
    let peer_id = PeerId::random();
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "linux-desktop".to_string());
    let peer_info = PeerInfo::new(peer_id.clone(), &hostname, "linux");

    info!("Peer ID: {}", peer_id);
    info!("Device:  {}", hostname);
    info!("Port:    {}/udp (QUIC)", shunkan_core::DEFAULT_PORT);

    // Detect the display session type for clipboard strategy.
    let session_type = SessionType::detect();
    info!("Session: {}", session_type.label());

    // Spawn mDNS discovery task.
    let mdns_handle = tokio::spawn(run_mdns_discovery(peer_info.clone()));

    // Spawn QUIC listener task.
    let quic_handle = tokio::spawn(run_quic_listener(peer_info.clone()));

    // Spawn clipboard monitor task.
    let clipboard_handle = tokio::spawn(run_clipboard_monitor(session_type, peer_id));

    info!("All services started. Press Ctrl+C to stop.");

    // Wait for Ctrl+C or any task to finish.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down...");
        }
        result = mdns_handle => {
            match result {
                Ok(Ok(())) => info!("mDNS discovery exited"),
                Ok(Err(e)) => error!("mDNS discovery error: {}", e),
                Err(e) => error!("mDNS task panicked: {}", e),
            }
        }
        result = quic_handle => {
            match result {
                Ok(Ok(())) => info!("QUIC listener exited"),
                Ok(Err(e)) => error!("QUIC listener error: {}", e),
                Err(e) => error!("QUIC task panicked: {}", e),
            }
        }
        result = clipboard_handle => {
            match result {
                Ok(Ok(())) => info!("Clipboard monitor exited"),
                Ok(Err(e)) => error!("Clipboard monitor error: {}", e),
                Err(e) => error!("Clipboard task panicked: {}", e),
            }
        }
    }

    info!("Shunkan daemon stopped.");
    Ok(())
}

/// Start mDNS-SD service discovery and advertisement.
///
/// Registers this peer as `_shunkan-sync._udp.local.` and listens for
/// other peers on the local network. Uses `shunkan_core::discovery`.
async fn run_mdns_discovery(peer_info: PeerInfo) -> Result<()> {
    info!(
        "Starting mDNS discovery (service: {})",
        shunkan_core::SERVICE_TYPE
    );

    // TODO: Wire to shunkan_core::discovery module once available.
    // The discovery module will:
    // 1. Register our service via mdns-sd
    // 2. Browse for other _shunkan-sync._udp.local. services
    // 3. Emit PeerInfo events for discovered peers

    info!(
        "mDNS stub: would advertise '{}' as {}",
        peer_info.device_name, shunkan_core::SERVICE_TYPE
    );

    // Keep alive until cancelled.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        info!("mDNS heartbeat — scanning for peers...");
    }
}

/// Start the QUIC transport listener on the default port.
///
/// Accepts incoming connections from paired peers and handles
/// clipboard sync and file transfer streams.
async fn run_quic_listener(peer_info: PeerInfo) -> Result<()> {
    info!(
        "Starting QUIC listener on 0.0.0.0:{}",
        shunkan_core::DEFAULT_PORT
    );

    // TODO: Wire to shunkan_core::transport module once available.
    // The transport module will:
    // 1. Generate self-signed TLS certs via rcgen
    // 2. Create a quinn::Endpoint bound to DEFAULT_PORT
    // 3. Accept incoming QUIC connections
    // 4. Multiplex clipboard (Stream 1) and file transfer (Stream 0)

    info!(
        "QUIC stub: would listen on port {} for peer '{}'",
        shunkan_core::DEFAULT_PORT,
        peer_info.device_name
    );

    // Keep alive until cancelled.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        info!("QUIC heartbeat — listening for connections...");
    }
}

/// Start the clipboard monitoring loop.
///
/// Polls the system clipboard for changes using the appropriate backend
/// for the detected session type. New clipboard content is hashed with
/// BLAKE3 for dedup and broadcast to connected peers.
async fn run_clipboard_monitor(session_type: SessionType, peer_id: PeerId) -> Result<()> {
    info!(
        "Starting clipboard monitor (session: {})",
        session_type.label()
    );

    let monitor = ClipboardMonitor::with_session_type(session_type);

    monitor
        .run_monitor_loop(move |text| {
            // TODO: Wire to shunkan_core::transport to broadcast to peers.
            info!(
                "New clipboard content ({} bytes) — would broadcast to peers",
                text.len()
            );

            // Create a ClipboardItem for the protocol.
            let item = shunkan_core::protocol::ClipboardItem::from_text(
                text,
                peer_id.clone(),
            );
            info!(
                "Created ClipboardItem (hash: {}...)",
                &item.content_hash[..8]
            );
        })
        .await
}

//! Shunkan Desktop Linux — headless daemon.
//!
//! This crate is the P2P clipboard sync daemon for Linux. It will eventually be
//! wrapped by Tauri v2 for the system tray UI, so the daemon lives in the
//! library and the binary is a thin entry point — that is the shape Tauri v2
//! expects, and it keeps the IPC surface in [`commands`] reachable and testable
//! without a running UI.
//!
//! ## What it does
//!
//! 1. Initializes logging (via `RUST_LOG` env var)
//! 2. Loads (or creates) this device's persistent identity and trust store
//! 3. Detects the display session type (X11 / Wayland / GNOME)
//! 4. Starts the QUIC transport listener on port 4433/udp
//! 5. Advertises and browses `_shunkan-sync._udp.local.` over mDNS-SD
//! 6. Connects to discovered peers and syncs clipboard content both ways
//!
//! ## Pairing
//!
//! A device only talks to peers whose certificate fingerprint it has pinned
//! *and* PIN-confirmed. Mutual TLS enforces the pin in both directions; the PIN
//! is confirmed by a SPAKE2 exchange bound to both certificate fingerprints.
//!
//! To pair two devices:
//!
//! ```text
//! # on the first device — prints a PIN
//! SHUNKAN_PAIRING=1 shunkan-desktop
//!
//! # on the second device — enter the PIN it printed
//! SHUNKAN_PAIRING_PIN=314159 shunkan-desktop
//! ```
//!
//! After that both restart without either variable and reconnect silently.

pub mod clipboard;
pub mod commands;
pub mod peer;
pub mod state;

use anyhow::{Context, Result};
use clipboard::{ClipboardMonitor, SessionType};
use log::{error, info, warn};
use shunkan_core::crypto::PairingPin;
use shunkan_core::discovery::{DiscoveryEvent, DiscoveryService, ServiceAdvertisement};
use shunkan_core::identity::{self, DeviceIdentity};
use shunkan_core::protocol::{ClipboardItem, PeerInfo};
use shunkan_core::transport::{TransportClient, TransportConfig, TransportServer};
use shunkan_core::trust::TrustStore;
use state::AppState;
use std::sync::Arc;

/// Environment variable that opens a pairing window with a generated PIN.
pub const PAIRING_ENV: &str = "SHUNKAN_PAIRING";

/// Environment variable carrying the PIN shown by the other device.
pub const PAIRING_PIN_ENV: &str = "SHUNKAN_PAIRING_PIN";

/// Resolve the pairing PIN from the environment, generating one if the operator
/// asked to pair without supplying it.
///
/// Returns `None` when pairing is not requested, which is the normal case: a
/// device with confirmed pairings needs no PIN to reconnect to them.
fn resolve_pairing_pin() -> Result<Option<PairingPin>> {
    if let Ok(raw) = std::env::var(PAIRING_PIN_ENV) {
        let pin = PairingPin::parse(raw.trim())
            .with_context(|| format!("{} must be exactly 6 digits", PAIRING_PIN_ENV))?;
        info!("Pairing armed with the PIN supplied in {}", PAIRING_PIN_ENV);
        return Ok(Some(pin));
    }

    if std::env::var(PAIRING_ENV).is_ok_and(|v| v != "0") {
        let pin = PairingPin::generate();
        warn!("╔══════════════════════════════════════════════╗");
        warn!("║  PAIRING PIN: {}                        ║", pin);
        warn!("║  Start the other device with:                ║");
        warn!("║    {}={}          ║", PAIRING_PIN_ENV, pin.as_str());
        warn!("╚══════════════════════════════════════════════╝");
        return Ok(Some(pin));
    }

    Ok(None)
}

/// Initialize logging — defaults to info level if `RUST_LOG` is not set.
pub fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();
}

/// Run the daemon until Ctrl+C or a fatal service error.
pub async fn run() -> Result<()> {
    info!("╔══════════════════════════════════════════════╗");
    info!("║  Shunkan P2P Engine — Desktop Linux Daemon   ║");
    info!(
        "║  瞬間 (Shunkan) v{}                    ║",
        env!("CARGO_PKG_VERSION")
    );
    info!("╚══════════════════════════════════════════════╝");

    // Load the persistent device identity. Restarting must not look like a new
    // device to peers that have already paired with us.
    let data_dir = identity::default_data_dir();
    let device_identity = Arc::new(
        DeviceIdentity::load_or_create(&data_dir)
            .context("Failed to load or create the device identity")?,
    );
    let trust = Arc::new(
        TrustStore::load_or_create(&data_dir).context("Failed to load the paired-device store")?,
    );

    let pairing_pin = resolve_pairing_pin()?;
    if pairing_pin.is_none() && trust.is_empty() {
        warn!(
            "No paired devices yet. Start one device with {}=1 to get a PIN, then \
             the other with {}=<that PIN>.",
            PAIRING_ENV, PAIRING_PIN_ENV
        );
    }

    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "linux-desktop".to_string());
    let peer_info = PeerInfo::new(device_identity.peer_id().clone(), &hostname, "linux");

    info!("Peer ID: {}", peer_info.id);
    info!("Device:  {}", hostname);
    info!("Fingerprint: {}", device_identity.fingerprint());
    info!("Paired:  {} device(s)", trust.len());
    info!("Data:    {}", data_dir.display());

    // Detect the display session type for clipboard strategy.
    let session_type = SessionType::detect();
    info!("Session: {}", session_type.label());

    // Bind the QUIC listener first so we advertise the port we actually got.
    let server = TransportServer::start(
        TransportConfig {
            bind_addr: ([0, 0, 0, 0], shunkan_core::DEFAULT_PORT).into(),
            ..TransportConfig::default()
        },
        &device_identity,
        trust.clone(),
    )
    .await
    .context("Failed to start the QUIC listener")?;
    let listening_port = server.local_addr()?.port();
    info!("Port:    {}/udp (QUIC)", listening_port);

    let clipboard = Arc::new(ClipboardMonitor::with_session_type(session_type));
    let app_state = Arc::new(AppState::new(
        device_identity.clone(),
        trust.clone(),
        peer_info.clone(),
        session_type,
        listening_port,
        clipboard.clone(),
    ));
    // Arming the PIN is what turns pairing mode on, so the two can never be
    // out of step — a pairing window without a PIN would be an open door.
    app_state.set_pairing_pin(pairing_pin);

    let listener_handle = tokio::spawn(run_quic_listener(app_state.clone(), server));
    let mdns_handle = tokio::spawn(run_mdns_discovery(
        app_state.clone(),
        hostname.clone(),
        listening_port,
    ));
    let clipboard_handle = tokio::spawn(run_clipboard_monitor(app_state.clone(), clipboard));

    info!("All services started. Press Ctrl+C to stop.");

    // Wait for Ctrl+C or any task to finish.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down...");
        }
        result = mdns_handle => report("mDNS discovery", result),
        result = listener_handle => report("QUIC listener", result),
        result = clipboard_handle => report("Clipboard monitor", result),
    }

    info!("Shunkan daemon stopped.");
    Ok(())
}

/// Log how a service task ended.
fn report(name: &str, result: std::result::Result<Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => info!("{} exited", name),
        Ok(Err(e)) => error!("{} error: {}", name, e),
        Err(e) => error!("{} task panicked: {}", name, e),
    }
}

/// Advertise this device over mDNS-SD and dial the peers we discover.
async fn run_mdns_discovery(state: Arc<AppState>, hostname: String, port: u16) -> Result<()> {
    info!(
        "Starting mDNS discovery (service: {})",
        shunkan_core::SERVICE_TYPE
    );

    let mut discovery = DiscoveryService::new().context("Failed to start the mDNS daemon")?;
    let mut events = discovery.browse().context("Failed to browse for peers")?;

    let advertisement = ServiceAdvertisement::new(
        state.peer_id().0.clone(),
        "linux",
        state.identity.fingerprint(),
    );
    let instance_name = sanitize_instance_name(&hostname);
    discovery
        .register(&instance_name, port, &advertisement)
        .context("Failed to advertise over mDNS")?;

    let client = Arc::new(
        TransportClient::new(&state.identity, state.trust.clone())
            .context("Failed to create the QUIC client endpoint")?,
    );

    while let Some(event) = events.recv().await {
        match event {
            DiscoveryEvent::PeerDiscovered(discovered) => {
                let Some(advertisement) = discovered.advertisement.clone() else {
                    log::debug!(
                        "Ignoring {} — no Shunkan TXT record",
                        discovered.instance_name
                    );
                    continue;
                };
                let peer_id = shunkan_core::protocol::PeerId::new(advertisement.peer_id.clone());

                if state.has_peer(&peer_id) {
                    log::trace!("Already connected to {}", peer_id);
                    continue;
                }
                if !peer::should_dial(&state.peer_id().0, &advertisement.peer_id) {
                    log::debug!("Waiting for {} to dial us (tie-break)", peer_id);
                    continue;
                }
                let Some(addr) = discovered.socket_addr() else {
                    warn!(
                        "Discovered {} but it advertised no reachable address",
                        peer_id
                    );
                    continue;
                };

                let server_name = identity::dns_name_for(&peer_id);
                tokio::spawn(peer::dial(
                    state.clone(),
                    client.clone(),
                    addr,
                    server_name,
                    peer_id.0.clone(),
                ));
            }
            DiscoveryEvent::PeerRemoved(fullname) => {
                log::info!("Peer left the network: {}", fullname);
            }
        }
    }

    Ok(())
}

/// Accept inbound QUIC connections until the endpoint closes.
async fn run_quic_listener(state: Arc<AppState>, server: TransportServer) -> Result<()> {
    info!("QUIC listener accepting connections");

    loop {
        match server.accept().await {
            Ok(Some(conn)) => {
                tokio::spawn(peer::serve_inbound(state.clone(), conn));
            }
            Ok(None) => {
                info!("QUIC endpoint closed");
                return Ok(());
            }
            Err(e) => {
                // A rejected handshake (an unpaired peer, say) is routine and
                // must not take the listener down with it.
                warn!("Rejected inbound connection: {}", e);
            }
        }
    }
}

/// Watch the local clipboard and fan changes out to connected peers.
async fn run_clipboard_monitor(
    state: Arc<AppState>,
    clipboard: Arc<ClipboardMonitor>,
) -> Result<()> {
    info!(
        "Starting clipboard monitor (session: {})",
        state.session_type.label()
    );

    let peer_id = state.peer_id().clone();
    clipboard
        .run_monitor_loop(move |text| {
            let item = ClipboardItem::from_text(text, peer_id.clone());
            let hash_prefix = item.content_hash[..8].to_string();
            let bytes = item.data.len();

            if !state.record_clipboard(item.clone()) {
                log::debug!(
                    "Local clipboard content already in history ({}…)",
                    hash_prefix
                );
            }

            let delivered = state.broadcast_clipboard(&item);
            info!(
                "Clipboard {}… ({} bytes) sent to {} peer(s)",
                hash_prefix, bytes, delivered
            );
        })
        .await
}

/// Turn a hostname into a valid, readable mDNS instance name.
fn sanitize_instance_name(hostname: &str) -> String {
    let cleaned: String = hostname
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
        "shunkan-device".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_instance_name() {
        assert_eq!(
            sanitize_instance_name("helliot-thinkpad"),
            "helliot-thinkpad"
        );
        assert_eq!(sanitize_instance_name("my box.local"), "my-box-local");
        assert_eq!(sanitize_instance_name("--"), "shunkan-device");
        assert_eq!(sanitize_instance_name(""), "shunkan-device");
    }
}

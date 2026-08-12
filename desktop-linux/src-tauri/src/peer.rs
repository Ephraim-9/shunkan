//! Peer connection lifecycle: handshake, writer task, and receive loop.
//!
//! One connection carries one long-lived control channel. After both sides
//! exchange a [`Handshake`], a writer task drains the peer's outbound queue
//! onto the control stream while the receive loop applies inbound clipboard
//! items to local history and to the system clipboard.

use crate::state::{now_secs, AppState, Outbound, PeerHandle};
use anyhow::{bail, Context, Result};
use shunkan_core::pairing::{ChannelBinding, PairingRole, PairingSession};
use shunkan_core::protocol::{ContentType, Handshake, Message, PeerInfo};
use shunkan_core::transport::{ControlChannel, TransportConnection};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// How long a peer has to complete the handshake before we hang up.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long each step of the pairing exchange may take.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(30);

/// Which side of the connection we are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// We dialled the peer, so we open the control channel.
    Dialer,
    /// The peer dialled us, so we accept the control channel.
    Listener,
}

/// Decide whether we should dial a discovered peer, or wait for it to dial us.
///
/// Both devices discover each other at roughly the same moment, so without a
/// rule they would each dial and end up with two connections. Comparing peer
/// IDs gives both sides the same answer without any negotiation: the lower ID
/// dials.
pub fn should_dial(our_peer_id: &str, their_peer_id: &str) -> bool {
    our_peer_id < their_peer_id
}

/// Run a peer connection to completion.
///
/// Returns when the connection closes or errors. The peer is registered in
/// [`AppState`] for the duration and removed on the way out, whatever the
/// outcome.
pub async fn serve(state: Arc<AppState>, conn: TransportConnection, role: Role) -> Result<()> {
    let addr = conn.remote_address();
    let fingerprint = conn.peer_fingerprint();

    let mut control = match role {
        Role::Dialer => conn.open_control().await?,
        Role::Listener => conn.accept_control().await?,
    };

    // Mutual TLS means both sides authenticated a certificate; without a
    // fingerprint we cannot bind a pairing to this channel, so there is nothing
    // safe to do with the connection.
    let fingerprint =
        fingerprint.ok_or_else(|| anyhow::anyhow!("Peer at {} presented no certificate", addr))?;

    // Send ours first so neither side waits on the other to speak.
    control
        .send(&Message::Handshake(Handshake::new(state.peer_info.clone())))
        .await
        .context("Failed to send handshake")?;

    // F-16: the first frame on a new connection must be a handshake, and it
    // must arrive promptly. Anything else closes the connection.
    let peer_info = tokio::time::timeout(HANDSHAKE_TIMEOUT, control.recv())
        .await
        .map_err(|_| anyhow::anyhow!("Peer at {} did not complete a handshake in time", addr))?
        .context("Failed to read peer handshake")
        .and_then(|msg| match msg {
            Message::Handshake(hs) => Ok(hs.peer_info),
            other => bail!(
                "Expected a handshake as the first frame from {}, got {:?}",
                addr,
                other
            ),
        })?;

    if peer_info.id == state.peer_info.id {
        bail!("Refusing to connect to ourselves ({})", peer_info.id);
    }

    // A certificate pinned during trust-on-first-use is not yet a pairing: it
    // is enough to carry the PIN exchange and nothing else. Run that exchange
    // now, and tear the connection down if it fails.
    if !state.trust.is_trusted_fingerprint(&fingerprint) {
        match run_pairing(&state, &mut control, &peer_info, &fingerprint, role).await {
            Ok(()) => {}
            Err(e) => {
                // Do not leave a usable pin behind after a failed attempt.
                if let Err(cleanup) = state.trust.forget_unconfirmed_fingerprint(&fingerprint) {
                    log::warn!("Failed to drop the unconfirmed pin: {}", cleanup);
                }
                let _ = control
                    .send(&Message::PairingResult {
                        accepted: false,
                        reason: Some(e.to_string()),
                    })
                    .await;
                conn.close();
                return Err(e.context(format!("Pairing with {} failed", peer_info.device_name)));
            }
        }
    }

    control.set_peer_label(peer_info.device_name.clone());
    let (mut sender, mut receiver) = control.split();

    let (tx, mut rx) = mpsc::unbounded_channel::<Outbound>();
    let peer_id = peer_info.id.clone();
    state.add_peer(PeerHandle::new(
        peer_info.clone(),
        addr,
        Some(fingerprint),
        tx.clone(),
    ));

    // Writer task: the only thing that touches the send half, which is what
    // keeps clipboard sequence numbers monotonic.
    let writer_label = peer_info.device_name.clone();
    let writer = tokio::spawn(async move {
        while let Some(outbound) = rx.recv().await {
            let result = match outbound {
                Outbound::Clipboard(item) => sender.send_clipboard(*item).await,
                Outbound::Message(msg) => sender.send(&msg).await,
            };
            if let Err(e) = result {
                log::warn!("Send to {} failed: {}", writer_label, e);
                break;
            }
        }
        let _ = sender.finish();
    });

    let result = receive_loop(&state, &mut receiver, &peer_info, &tx).await;

    state.remove_peer(&peer_id);
    drop(tx);
    writer.abort();
    conn.close();

    result
}

/// Run the PIN pairing exchange over an established, provisionally trusted
/// connection.
///
/// On success the peer's certificate is promoted to a confirmed pairing and
/// will be accepted on every future connection without a PIN. On failure the
/// caller drops the provisional pin and closes the connection.
async fn run_pairing(
    state: &Arc<AppState>,
    control: &mut ControlChannel,
    peer_info: &PeerInfo,
    peer_fingerprint: &str,
    role: Role,
) -> Result<()> {
    let Some(pin) = state.pairing_pin() else {
        bail!(
            "{} is not a paired device and no pairing PIN is configured — start \
             the daemon with {}=<6 digits> on both devices to pair them",
            peer_info.device_name,
            crate::PAIRING_PIN_ENV
        );
    };

    // A PAKE gives an attacker one online guess per exchange. Over a six-digit
    // space that is still 10^6 exchanges, so ration the guesses too.
    state
        .pairing_attempts
        .check(&peer_info.id.0)
        .context("Pairing refused")?;

    let pairing_role = match role {
        Role::Dialer => PairingRole::Initiator,
        Role::Listener => PairingRole::Responder,
    };
    let (initiator_id, responder_id) = match pairing_role {
        PairingRole::Initiator => (state.peer_id().0.clone(), peer_info.id.0.clone()),
        PairingRole::Responder => (peer_info.id.0.clone(), state.peer_id().0.clone()),
    };

    let binding = ChannelBinding::new(pairing_role, state.identity.fingerprint(), peer_fingerprint);

    log::info!(
        "Starting PIN pairing with {} as {:?}",
        peer_info.device_name,
        pairing_role
    );

    let session = PairingSession::start(&pin, pairing_role, &initiator_id, &responder_id, binding);

    control
        .send(&Message::PairingHello {
            spake: session.outbound_message().to_vec(),
        })
        .await
        .context("Failed to send the pairing message")?;

    let peer_spake = match recv_within(control, PAIRING_TIMEOUT).await? {
        Message::PairingHello { spake } => spake,
        other => bail!("Expected a pairing message, got {:?}", other),
    };

    let confirmation = match session.finish(&peer_spake) {
        Ok(confirmation) => confirmation,
        Err(e) => {
            state.pairing_attempts.record_failure(&peer_info.id.0);
            return Err(e);
        }
    };

    control
        .send(&Message::PairingConfirm {
            mac: confirmation.our_mac(),
        })
        .await
        .context("Failed to send the pairing confirmation")?;

    let peer_mac = match recv_within(control, PAIRING_TIMEOUT).await? {
        Message::PairingConfirm { mac } => mac,
        Message::PairingResult { reason, .. } => {
            state.pairing_attempts.record_failure(&peer_info.id.0);
            bail!(
                "{} rejected the pairing: {}",
                peer_info.device_name,
                reason.unwrap_or_else(|| "no reason given".into())
            );
        }
        other => bail!("Expected a pairing confirmation, got {:?}", other),
    };

    if !confirmation.verify_peer_mac(&peer_mac) {
        state.pairing_attempts.record_failure(&peer_info.id.0);
        bail!(
            "Pairing confirmation from {} did not verify — wrong PIN, or the \
             connection is being relayed",
            peer_info.device_name
        );
    }

    state.pairing_attempts.record_success(&peer_info.id.0);
    state
        .trust
        .confirm(
            peer_fingerprint,
            &peer_info.id.0,
            &peer_info.device_name,
            &peer_info.platform,
        )
        .context("Failed to record the confirmed pairing")?;

    control
        .send(&Message::PairingResult {
            accepted: true,
            reason: None,
        })
        .await
        .context("Failed to send the pairing result")?;

    log::info!("Paired with {} ({})", peer_info.device_name, peer_info.id);
    Ok(())
}

/// Receive the next control message, failing if it does not arrive in time.
async fn recv_within(control: &mut ControlChannel, timeout: Duration) -> Result<Message> {
    tokio::time::timeout(timeout, control.recv())
        .await
        .map_err(|_| anyhow::anyhow!("Peer did not respond within {:?}", timeout))?
}

/// Apply inbound messages until the connection ends.
async fn receive_loop(
    state: &Arc<AppState>,
    receiver: &mut shunkan_core::transport::ControlReceiver,
    peer_info: &PeerInfo,
    tx: &mpsc::UnboundedSender<Outbound>,
) -> Result<()> {
    loop {
        let msg = match receiver.recv().await {
            Ok(msg) => msg,
            Err(e) => {
                log::debug!("Connection to {} ended: {}", peer_info.device_name, e);
                return Ok(());
            }
        };

        match msg {
            Message::Clipboard { seq, item } => {
                log::info!(
                    "Received clipboard item seq={} ({} bytes) from {}",
                    seq,
                    item.data.len(),
                    peer_info.device_name
                );
                apply_remote_clipboard(state, item);
            }
            Message::Ping { timestamp } => {
                let _ = tx.send(Outbound::Message(Box::new(Message::Pong { timestamp })));
            }
            Message::Pong { timestamp } => {
                log::trace!("Pong from {} ({})", peer_info.device_name, timestamp);
            }
            Message::Handshake(_) => {
                log::warn!("Ignoring repeat handshake from {}", peer_info.device_name);
            }
            Message::PairingHello { .. }
            | Message::PairingConfirm { .. }
            | Message::PairingResult { .. } => {
                // Pairing runs to completion before this loop starts. A pairing
                // message here means the peer is trying to re-run the exchange
                // on an already-trusted connection, which is not a thing.
                log::warn!(
                    "Ignoring out-of-band pairing message from {}",
                    peer_info.device_name
                );
            }
            Message::FileChunk(chunk) => {
                // File transfers use their own streams; a chunk on the control
                // channel is a protocol error rather than something to reassemble.
                log::warn!(
                    "Ignoring file chunk {} of transfer {} on the control channel",
                    chunk.chunk_index,
                    chunk.transfer_id
                );
            }
            Message::Ack(ack) => {
                log::debug!(
                    "Transfer {} acknowledged by {} (success={})",
                    ack.transfer_id,
                    peer_info.device_name,
                    ack.success
                );
            }
        }
    }
}

/// Store a remote clipboard item and, for text, put it on the system clipboard.
fn apply_remote_clipboard(state: &Arc<AppState>, item: shunkan_core::protocol::ClipboardItem) {
    let text = match item.content_type {
        ContentType::PlainText | ContentType::RichText | ContentType::FileUri => {
            String::from_utf8(item.data.clone()).ok()
        }
        ContentType::Image => None,
    };

    if !state.record_clipboard(item) {
        log::debug!("Remote clipboard item deduplicated against existing history entry");
    }

    if let Some(text) = text {
        if let Err(e) = state.clipboard().write_to_clipboard(&text) {
            log::warn!("Failed to write remote clipboard content locally: {}", e);
        }
    }
}

/// Handle one accepted inbound connection, logging rather than propagating
/// errors so a single bad peer cannot stop the listener.
pub async fn serve_inbound(state: Arc<AppState>, conn: TransportConnection) {
    let addr = conn.remote_address();
    if let Err(e) = serve(state, conn, Role::Listener).await {
        log::warn!("Inbound connection from {} failed: {}", addr, e);
    }
}

/// Dial a discovered peer and serve the resulting connection.
pub async fn dial(
    state: Arc<AppState>,
    client: Arc<shunkan_core::transport::TransportClient>,
    addr: std::net::SocketAddr,
    server_name: String,
    label: String,
) {
    log::info!("Dialling {} at {}", label, addr);
    let conn = match client.connect(addr, &server_name).await {
        Ok(conn) => conn,
        Err(e) => {
            log::warn!("Could not connect to {} at {}: {}", label, addr, e);
            return;
        }
    };

    let connected_at = now_secs();
    if let Err(e) = serve(state, conn, Role::Dialer).await {
        log::warn!("Connection to {} failed: {}", label, e);
    }
    log::debug!(
        "Connection to {} lasted {}s",
        label,
        now_secs().saturating_sub(connected_at)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dial_tie_break_is_total_and_antisymmetric() {
        assert!(should_dial("peer-0001", "peer-0002"));
        assert!(!should_dial("peer-0002", "peer-0001"));
        // Exactly one side of any pair dials.
        assert_ne!(
            should_dial("peer-aaaa", "peer-bbbb"),
            should_dial("peer-bbbb", "peer-aaaa")
        );
    }

    #[test]
    fn test_we_never_dial_ourselves() {
        assert!(!should_dial("peer-same", "peer-same"));
    }
}

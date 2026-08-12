//! QUIC transport layer using the `quinn` crate.
//!
//! Provides the core networking abstraction for Shunkan P2P communication.
//! Uses QUIC over UDP (port 4433 by default per ADR-001) with TLS 1.3
//! certificates taken from a persisted [`DeviceIdentity`] and verified against
//! pinned fingerprints in a [`TrustStore`].
//!
//! ## Stream discipline
//!
//! QUIC streams are independent and unordered *relative to each other* — that
//! is the head-of-line-blocking property the architecture praises. Applied per
//! message it becomes a bug: a stale clipboard item can land after and
//! overwrite a newer one.
//!
//! So streams here are logical channels, not envelopes:
//!
//! - One long-lived **control channel** (a bidirectional stream) carries the
//!   handshake, clipboard items, pings and acks, in order.
//! - Each file transfer gets **its own unidirectional stream**, so a large
//!   transfer never blocks clipboard traffic and its chunks stay in order
//!   within the transfer.

use crate::crypto;
use crate::identity::DeviceIdentity;
use crate::protocol::{ClipboardItem, FileChunk, Message};
use crate::trust::TrustStore;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Maximum accepted size of a frame on the control channel.
///
/// Clipboard text and small images travel here; anything larger belongs in a
/// file transfer. Deliberately far below the old blanket 16 MiB: the length
/// prefix comes off the wire from a peer we have not finished authenticating,
/// and it used to become a `vec![0u8; len]` directly.
pub const MAX_CONTROL_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Maximum accepted size of a frame on a file transfer stream.
///
/// A [`crate::DEFAULT_CHUNK_SIZE`] chunk is 64 KiB, which the JSON envelope
/// inflates to roughly 235 KiB. 1 MiB leaves headroom without letting a peer
/// name an arbitrary number.
pub const MAX_FILE_FRAME_SIZE: usize = 1024 * 1024;

/// Largest frame any stream will accept, whatever its role.
pub const MAX_MESSAGE_SIZE: usize = MAX_CONTROL_FRAME_SIZE;

/// Concurrent unidirectional streams a peer may open (one per file transfer).
///
/// Streams were unbounded, so a peer could open them in a loop and multiply the
/// per-stream allocation ceiling without limit — against a daemon whose stated
/// hard ceiling is 20 MB total (INV-01).
pub const MAX_CONCURRENT_UNI_STREAMS: u32 = 16;

/// Concurrent bidirectional streams a peer may open. One control channel is
/// all a well-behaved peer needs; the rest is slack for reconnection.
pub const MAX_CONCURRENT_BIDI_STREAMS: u32 = 4;

/// Multiple of the keep-alive interval used as the idle timeout.
///
/// Three missed keep-alives before a connection is declared dead: long enough
/// to ride out a brief Wi-Fi hiccup, short enough that a genuinely gone peer is
/// noticed quickly.
const IDLE_TIMEOUT_MULTIPLIER: u32 = 3;

/// Build the quinn transport parameters for a given configuration.
///
/// `keep_alive_ms` was set, defaulted, and asserted in three tests, but never
/// reached a `quinn::TransportConfig` — so a paired connection died at quinn's
/// default idle timeout with nothing to notice or reconnect. It is applied here,
/// along with a matching idle timeout.
fn quinn_transport_config(config: &TransportConfig) -> Result<Arc<quinn::TransportConfig>> {
    let mut quinn_config = quinn::TransportConfig::default();
    quinn_config.max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into());
    quinn_config.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());

    if config.keep_alive_ms > 0 {
        let interval = Duration::from_millis(config.keep_alive_ms);
        quinn_config.keep_alive_interval(Some(interval));

        let idle = interval
            .checked_mul(IDLE_TIMEOUT_MULTIPLIER)
            .context("keep_alive_ms is too large to derive an idle timeout from")?;
        let idle: quinn::IdleTimeout = quinn::VarInt::try_from(idle.as_millis() as u64)
            .map_err(|_| anyhow::anyhow!("keep_alive_ms is too large for a QUIC idle timeout"))?
            .into();
        quinn_config.max_idle_timeout(Some(idle));
    } else {
        // Explicitly disabled: no keep-alives, and no idle timeout to trip over.
        quinn_config.keep_alive_interval(None);
        quinn_config.max_idle_timeout(None);
    }

    Ok(Arc::new(quinn_config))
}

/// Reads length-prefixed frames into a reusable buffer with a hard ceiling.
///
/// Two properties matter here. The declared length is checked against `limit`
/// *before* any memory is reserved, and the buffer is reused across frames
/// rather than allocated fresh from a number the peer chose.
pub struct FrameReader {
    buf: Vec<u8>,
    limit: usize,
}

impl FrameReader {
    /// Create a reader that refuses frames larger than `limit` bytes.
    pub fn new(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            limit,
        }
    }

    /// The frame size ceiling this reader enforces.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Read the next frame from `recv`.
    pub async fn read(&mut self, recv: &mut quinn::RecvStream) -> Result<Message> {
        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf)
            .await
            .context("Failed to read frame length")?;
        let len = u32::from_be_bytes(len_buf) as usize;

        anyhow::ensure!(
            len <= self.limit,
            "Frame too large: {} bytes (max {})",
            len,
            self.limit
        );

        // Only now, with `len` known to be within the ceiling, is memory touched.
        self.buf.clear();
        self.buf.resize(len, 0);
        recv.read_exact(&mut self.buf)
            .await
            .context("Failed to read frame body")?;

        Message::from_bytes(&self.buf)
    }
}

/// Configuration for the QUIC transport layer.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// The local address to bind to.
    pub bind_addr: SocketAddr,
    /// Keep-alive interval in milliseconds (0 to disable).
    pub keep_alive_ms: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], crate::DEFAULT_PORT)),
            keep_alive_ms: 5000,
        }
    }
}

/// A QUIC transport server that listens for incoming connections.
pub struct TransportServer {
    endpoint: quinn::Endpoint,
    _config: TransportConfig,
}

impl TransportServer {
    /// Create and start a new QUIC transport server.
    ///
    /// Presents `identity`'s persisted certificate, so a peer that paired with
    /// this device in an earlier run still recognizes it, and requires the
    /// inbound peer to present a certificate pinned in `trust`.
    pub async fn start(
        config: TransportConfig,
        identity: &DeviceIdentity,
        trust: Arc<TrustStore>,
    ) -> Result<Self> {
        let mut server_config = crypto::quinn_server_config(identity, trust)
            .context("Failed to build QUIC server config from device identity")?;
        server_config.transport_config(quinn_transport_config(&config)?);

        let endpoint = quinn::Endpoint::server(server_config, config.bind_addr)
            .context("Failed to bind QUIC endpoint")?;

        log::info!(
            "QUIC server listening on {} as {} (fingerprint {}…)",
            endpoint.local_addr().unwrap_or(config.bind_addr),
            identity.peer_id(),
            &identity.fingerprint()[..16]
        );

        Ok(Self {
            endpoint,
            _config: config,
        })
    }

    /// Accept the next incoming QUIC connection.
    ///
    /// Returns `Ok(None)` once the endpoint is closed.
    pub async fn accept(&self) -> Result<Option<TransportConnection>> {
        if let Some(incoming) = self.endpoint.accept().await {
            let connection = incoming
                .await
                .context("Failed to accept incoming QUIC connection")?;

            let remote_addr = connection.remote_address();
            log::info!("Accepted connection from {}", remote_addr);

            Ok(Some(TransportConnection { connection }))
        } else {
            Ok(None)
        }
    }

    /// Get the local address the server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("Failed to get local address")
    }

    /// Shut down the transport server gracefully.
    pub fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"server shutting down");
        log::info!("QUIC server shut down");
    }
}

/// A QUIC transport client for connecting to peers.
pub struct TransportClient {
    endpoint: quinn::Endpoint,
}

impl TransportClient {
    /// Create a new transport client that pins peers by certificate fingerprint
    /// and presents `identity` for the peer to authenticate in turn.
    pub fn new(identity: &DeviceIdentity, trust: Arc<TrustStore>) -> Result<Self> {
        Self::bind(
            "0.0.0.0:0".parse().expect("valid wildcard address"),
            identity,
            trust,
        )
    }

    /// Create a client with explicit transport parameters (keep-alive, limits).
    pub fn with_config(
        config: &TransportConfig,
        identity: &DeviceIdentity,
        trust: Arc<TrustStore>,
    ) -> Result<Self> {
        Self::bind_with_config(
            "0.0.0.0:0".parse().expect("valid wildcard address"),
            config,
            identity,
            trust,
        )
    }

    /// Create a transport client bound to a specific local address.
    pub fn bind(
        bind_addr: SocketAddr,
        identity: &DeviceIdentity,
        trust: Arc<TrustStore>,
    ) -> Result<Self> {
        Self::bind_with_config(bind_addr, &TransportConfig::default(), identity, trust)
    }

    /// Create a client bound to a specific address with explicit transport
    /// parameters.
    pub fn bind_with_config(
        bind_addr: SocketAddr,
        config: &TransportConfig,
        identity: &DeviceIdentity,
        trust: Arc<TrustStore>,
    ) -> Result<Self> {
        let mut client_config = crypto::quinn_client_config(identity, trust)
            .context("Failed to build QUIC client config")?;
        client_config.transport_config(quinn_transport_config(config)?);

        let mut endpoint =
            quinn::Endpoint::client(bind_addr).context("Failed to create client endpoint")?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint })
    }

    /// Connect to a remote peer.
    ///
    /// `server_name` is the peer's certificate SAN — see
    /// [`crate::identity::dns_name_for`]. It identifies the peer; the
    /// certificate fingerprint is what authorizes it.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<TransportConnection> {
        let connection = self
            .endpoint
            .connect(addr, server_name)
            .context("Failed to initiate QUIC connection")?
            .await
            .with_context(|| format!("Failed to establish QUIC connection to {}", addr))?;

        log::info!("Connected to {} ({})", addr, server_name);

        Ok(TransportConnection { connection })
    }

    /// Shut down the client endpoint.
    pub fn shutdown(&self) {
        self.endpoint.close(0u32.into(), b"client shutting down");
    }
}

/// An established QUIC connection to a peer.
pub struct TransportConnection {
    connection: quinn::Connection,
}

impl TransportConnection {
    /// Get the remote address of the connected peer.
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// The BLAKE3 fingerprint of the certificate the peer presented, if any.
    ///
    /// This is the value that was checked against the trust store during the
    /// handshake, so it is the connection's authenticated identity.
    pub fn peer_fingerprint(&self) -> Option<String> {
        let certs = self.connection.peer_identity()?;
        let certs = certs
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .ok()?;
        certs.first().map(crate::identity::fingerprint_of)
    }

    /// Open the connection's control channel.
    ///
    /// The dialling side calls this; the accepting side calls
    /// [`TransportConnection::accept_control`].
    pub async fn open_control(&self) -> Result<ControlChannel> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .context("Failed to open control stream")?;
        Ok(ControlChannel::new(send, recv))
    }

    /// Accept the connection's control channel.
    pub async fn accept_control(&self) -> Result<ControlChannel> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .context("Failed to accept control stream")?;
        Ok(ControlChannel::new(send, recv))
    }

    /// Open a dedicated unidirectional stream for one file transfer.
    pub async fn open_file_stream(&self) -> Result<quinn::SendStream> {
        self.connection
            .open_uni()
            .await
            .context("Failed to open file transfer stream")
    }

    /// Accept a dedicated unidirectional stream carrying one file transfer.
    pub async fn accept_file_stream(&self) -> Result<quinn::RecvStream> {
        self.connection
            .accept_uni()
            .await
            .context("Failed to accept file transfer stream")
    }

    /// Wait until the connection is closed, returning the reason.
    pub async fn closed(&self) -> quinn::ConnectionError {
        self.connection.closed().await
    }

    /// Close the connection gracefully.
    pub fn close(&self) {
        self.connection.close(0u32.into(), b"connection closed");
    }
}

/// The long-lived ordered stream carrying handshake, clipboard, and control
/// traffic for one connection.
pub struct ControlChannel {
    sender: ControlSender,
    receiver: ControlReceiver,
}

impl ControlChannel {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            sender: ControlSender { send, next_seq: 0 },
            receiver: ControlReceiver {
                recv,
                frames: FrameReader::new(MAX_CONTROL_FRAME_SIZE),
                last_clipboard_seq: None,
                peer_label: None,
            },
        }
    }

    /// Split into independently owned halves so one task can send while
    /// another receives.
    pub fn split(self) -> (ControlSender, ControlReceiver) {
        (self.sender, self.receiver)
    }

    /// Send a message on the control channel.
    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        self.sender.send(msg).await
    }

    /// Send a clipboard item, assigning it the next sequence number.
    pub async fn send_clipboard(&mut self, item: ClipboardItem) -> Result<()> {
        self.sender.send_clipboard(item).await
    }

    /// Receive the next in-order message.
    pub async fn recv(&mut self) -> Result<Message> {
        self.receiver.recv().await
    }

    /// Label the channel for logging.
    pub fn set_peer_label(&mut self, label: impl Into<String>) {
        self.receiver.set_peer_label(label);
    }
}

/// The sending half of a [`ControlChannel`].
pub struct ControlSender {
    send: quinn::SendStream,
    next_seq: u64,
}

impl ControlSender {
    /// Send a message on the control channel.
    pub async fn send(&mut self, msg: &Message) -> Result<()> {
        send_framed_within(&mut self.send, msg, MAX_CONTROL_FRAME_SIZE)
            .await
            .context("Failed to write message to control stream")
    }

    /// Send a clipboard item, assigning it the next sequence number.
    pub async fn send_clipboard(&mut self, item: ClipboardItem) -> Result<()> {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.send(&Message::Clipboard { seq, item }).await
    }

    /// The sequence number the next clipboard message will carry.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Finish the stream, signalling no more messages will be sent.
    pub fn finish(&mut self) -> Result<()> {
        self.send
            .finish()
            .context("Failed to finish control stream")
    }
}

/// The receiving half of a [`ControlChannel`].
pub struct ControlReceiver {
    recv: quinn::RecvStream,
    frames: FrameReader,
    last_clipboard_seq: Option<u64>,
    peer_label: Option<String>,
}

impl ControlReceiver {
    /// Receive the next in-order message.
    ///
    /// Clipboard messages whose sequence number does not advance are dropped
    /// and the next message is awaited instead, so a replayed or reordered
    /// item can never overwrite a newer one.
    pub async fn recv(&mut self) -> Result<Message> {
        loop {
            let msg = self.frames.read(&mut self.recv).await?;

            if let Message::Clipboard { seq, .. } = &msg {
                if let Some(last) = self.last_clipboard_seq {
                    if *seq <= last {
                        log::warn!(
                            "Dropping out-of-order clipboard message from {} (seq {} <= last {})",
                            self.label(),
                            seq,
                            last
                        );
                        continue;
                    }
                }
                self.last_clipboard_seq = Some(*seq);
            }

            return Ok(msg);
        }
    }

    /// The highest clipboard sequence number accepted so far.
    pub fn last_clipboard_seq(&self) -> Option<u64> {
        self.last_clipboard_seq
    }

    /// Label this half for logging.
    pub fn set_peer_label(&mut self, label: impl Into<String>) {
        self.peer_label = Some(label.into());
    }

    fn label(&self) -> &str {
        self.peer_label.as_deref().unwrap_or("peer")
    }
}

/// Send a framed message over a QUIC send stream, refusing oversized frames.
///
/// Checked on the way out too, so an over-large message fails here with a clear
/// error instead of being silently dropped by the peer's ceiling.
pub async fn send_framed(send: &mut quinn::SendStream, msg: &Message) -> Result<()> {
    send_framed_within(send, msg, MAX_FILE_FRAME_SIZE).await
}

/// Send a framed message, enforcing an explicit size ceiling.
pub async fn send_framed_within(
    send: &mut quinn::SendStream,
    msg: &Message,
    limit: usize,
) -> Result<()> {
    let framed = msg.to_framed_bytes()?;
    anyhow::ensure!(
        framed.len() - 4 <= limit,
        "Refusing to send a {} byte frame (max {})",
        framed.len() - 4,
        limit
    );
    send.write_all(&framed)
        .await
        .context("Failed to write framed message")?;
    Ok(())
}

/// Receive a framed message from a file transfer stream.
///
/// Prefer [`FrameReader`] when reading more than one frame from the same
/// stream — it reuses its buffer instead of allocating per frame.
pub async fn recv_framed(recv: &mut quinn::RecvStream) -> Result<Message> {
    FrameReader::new(MAX_FILE_FRAME_SIZE).read(recv).await
}

/// The metadata preceding a raw chunk payload on a file transfer stream.
///
/// Small and fixed-shape, so encoding it costs nothing. The chunk's *data* does
/// not appear here — it follows on the wire verbatim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChunkHeader {
    /// Identifier for the file transfer session.
    pub transfer_id: String,
    /// Original filename.
    pub filename: String,
    /// Total file size in bytes.
    pub total_size: u64,
    /// Zero-based chunk index.
    pub chunk_index: u32,
    /// Total number of chunks.
    pub total_chunks: u32,
    /// BLAKE3 hash of this chunk's data (INV-05).
    pub chunk_hash: String,
    /// Length of the payload that follows.
    pub data_len: u32,
}

/// Largest header a peer may declare, so a malicious length cannot allocate.
const MAX_CHUNK_HEADER_SIZE: usize = 8 * 1024;

/// Send a file chunk with its payload written straight to the wire.
///
/// The wire form is `[u32 header_len][postcard header][payload bytes]`. Chunk
/// data never passes through a serializer, so a transfer costs exactly its own
/// size plus a small constant per chunk — the "better still" half of F-20's fix.
pub async fn send_chunk_raw(send: &mut quinn::SendStream, chunk: &FileChunk) -> Result<()> {
    let data_len = u32::try_from(chunk.data.len())
        .map_err(|_| anyhow::anyhow!("Chunk of {} bytes is too large", chunk.data.len()))?;
    anyhow::ensure!(
        chunk.data.len() <= MAX_FILE_FRAME_SIZE,
        "Refusing to send a {} byte chunk (max {})",
        chunk.data.len(),
        MAX_FILE_FRAME_SIZE
    );

    let header = ChunkHeader {
        transfer_id: chunk.transfer_id.clone(),
        filename: chunk.filename.clone(),
        total_size: chunk.total_size,
        chunk_index: chunk.chunk_index,
        total_chunks: chunk.total_chunks,
        chunk_hash: chunk.chunk_hash.clone(),
        data_len,
    };
    let encoded = postcard::to_stdvec(&header)
        .map_err(|e| anyhow::anyhow!("Failed to encode chunk header: {}", e))?;
    anyhow::ensure!(
        encoded.len() <= MAX_CHUNK_HEADER_SIZE,
        "Chunk header of {} bytes exceeds the {} byte limit",
        encoded.len(),
        MAX_CHUNK_HEADER_SIZE
    );

    send.write_all(&(encoded.len() as u32).to_be_bytes())
        .await
        .context("Failed to write chunk header length")?;
    send.write_all(&encoded)
        .await
        .context("Failed to write chunk header")?;
    send.write_all(&chunk.data)
        .await
        .context("Failed to write chunk payload")?;
    Ok(())
}

/// Receive a chunk written by [`send_chunk_raw`].
///
/// `buf` is reused across calls so a transfer allocates once, not once per
/// chunk. Both declared lengths are checked against their ceilings before any
/// memory is reserved.
pub async fn recv_chunk_raw(
    recv: &mut quinn::RecvStream,
    buf: &mut Vec<u8>,
) -> Result<Option<FileChunk>> {
    let mut len_buf = [0u8; 4];
    // A clean end of stream is how a transfer finishes, not an error.
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(anyhow::Error::new(e).context("Failed to read chunk header length")),
    }

    let header_len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(
        header_len <= MAX_CHUNK_HEADER_SIZE,
        "Chunk header too large: {} bytes (max {})",
        header_len,
        MAX_CHUNK_HEADER_SIZE
    );

    buf.clear();
    buf.resize(header_len, 0);
    recv.read_exact(buf)
        .await
        .context("Failed to read chunk header")?;
    let header: ChunkHeader = postcard::from_bytes(buf)
        .map_err(|e| anyhow::anyhow!("Failed to decode chunk header: {}", e))?;

    let data_len = header.data_len as usize;
    anyhow::ensure!(
        data_len <= MAX_FILE_FRAME_SIZE,
        "Chunk payload too large: {} bytes (max {})",
        data_len,
        MAX_FILE_FRAME_SIZE
    );

    buf.clear();
    buf.resize(data_len, 0);
    recv.read_exact(buf)
        .await
        .context("Failed to read chunk payload")?;

    let chunk = FileChunk {
        transfer_id: header.transfer_id,
        filename: header.filename,
        total_size: header.total_size,
        chunk_index: header.chunk_index,
        total_chunks: header.total_chunks,
        chunk_hash: header.chunk_hash,
        data: std::mem::take(buf),
    };

    Ok(Some(chunk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PeerId;
    use crate::trust::PairedPeer;

    /// Two devices that have already paired: each pins the other's certificate
    /// fingerprint, and the server is running. Everything goes through the
    /// public API — no hand-built TLS configuration anywhere.
    ///
    /// Returns (server identity, client identity, client trust store, server,
    /// server address).
    async fn paired_server() -> (
        DeviceIdentity,
        DeviceIdentity,
        Arc<TrustStore>,
        TransportServer,
        SocketAddr,
    ) {
        let server_identity = DeviceIdentity::generate().unwrap();
        let client_identity = DeviceIdentity::generate().unwrap();

        let server_trust = Arc::new(TrustStore::in_memory());
        server_trust
            .pair(PairedPeer::new(
                client_identity.peer_id().0.clone(),
                "Client",
                "linux",
                client_identity.fingerprint(),
            ))
            .unwrap();

        let client_trust = Arc::new(TrustStore::in_memory());
        client_trust
            .pair(PairedPeer::new(
                server_identity.peer_id().0.clone(),
                "Server",
                "linux",
                server_identity.fingerprint(),
            ))
            .unwrap();

        let server = TransportServer::start(
            TransportConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                keep_alive_ms: 5000,
            },
            &server_identity,
            server_trust,
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();

        (server_identity, client_identity, client_trust, server, addr)
    }

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.bind_addr.port(), crate::DEFAULT_PORT);
        assert_eq!(config.keep_alive_ms, 5000);
    }

    #[test]
    fn test_transport_config_custom() {
        let config = TransportConfig {
            bind_addr: "127.0.0.1:5555".parse().unwrap(),
            keep_alive_ms: 10000,
        };
        assert_eq!(config.bind_addr.port(), 5555);
    }

    #[tokio::test]
    async fn test_server_start_and_addr() {
        let identity = DeviceIdentity::generate().unwrap();
        let config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(), // OS-assigned port
            keep_alive_ms: 5000,
        };
        let server = TransportServer::start(config, &identity, Arc::new(TrustStore::in_memory()))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        assert!(addr.port() > 0);
        server.shutdown();
    }

    #[tokio::test]
    async fn test_client_creation() {
        let identity = DeviceIdentity::generate().unwrap();
        let client = TransportClient::new(&identity, Arc::new(TrustStore::in_memory()));
        assert!(client.is_ok());
        if let Ok(c) = client {
            c.shutdown();
        }
    }

    /// The regression test for F-01. Before the fix, this failed with
    /// `BadSignature` because each side minted its own certificate and trusted
    /// only itself. It drives the real public API — no hand-built configs.
    #[tokio::test]
    async fn test_paired_peers_complete_a_roundtrip_through_the_public_api() {
        let (identity, client_identity, trust, server, addr) = paired_server().await;

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            let mut control = conn.accept_control().await.unwrap();
            let msg = control.recv().await.unwrap();
            control
                .send(&Message::Pong { timestamp: 99 })
                .await
                .unwrap();
            // Keep the connection alive until the client has read the reply.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            conn.close();
            server.shutdown();
            msg
        });

        let client = TransportClient::new(&client_identity, trust).unwrap();
        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();
        let mut control = conn.open_control().await.unwrap();
        control
            .send(&Message::Ping { timestamp: 42 })
            .await
            .unwrap();

        let reply = control.recv().await.unwrap();
        assert_eq!(reply, Message::Pong { timestamp: 99 });

        let received = server_task.await.unwrap();
        assert_eq!(received, Message::Ping { timestamp: 42 });

        conn.close();
        client.shutdown();
    }

    /// An unpaired peer must not get a connection at all — the fingerprint is
    /// checked during the TLS handshake, before any application data flows.
    /// An unpaired peer must not get a connection at all — the fingerprint is
    /// checked during the TLS handshake, before any application data flows.
    #[tokio::test]
    async fn test_unpaired_client_cannot_connect() {
        let identity = DeviceIdentity::generate().unwrap();
        let server = TransportServer::start(
            TransportConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                keep_alive_ms: 5000,
            },
            &identity,
            Arc::new(TrustStore::in_memory()),
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = server.accept().await;
        });

        // Empty trust store, pairing mode off.
        let client_identity = DeviceIdentity::generate().unwrap();
        let client =
            TransportClient::new(&client_identity, Arc::new(TrustStore::in_memory())).unwrap();
        let result = client.connect(addr, &identity.dns_name()).await;

        assert!(result.is_err(), "unpaired peer must be refused");
        client.shutdown();
    }

    /// The other half of F-16: even a client that trusts the server is refused
    /// unless the *server* has pinned the client. Before mutual TLS, `accept()`
    /// returned every incoming connection with no validation at all.
    #[tokio::test]
    async fn test_server_refuses_a_client_it_has_not_pinned() {
        let server_identity = DeviceIdentity::generate().unwrap();
        let client_identity = DeviceIdentity::generate().unwrap();

        // The server pins nobody.
        let server = TransportServer::start(
            TransportConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                keep_alive_ms: 5000,
            },
            &server_identity,
            Arc::new(TrustStore::in_memory()),
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = server.accept().await;
        });

        // The client, however, trusts the server perfectly well.
        let client_trust = Arc::new(TrustStore::in_memory());
        client_trust
            .pair(PairedPeer::new(
                server_identity.peer_id().0.clone(),
                "Server",
                "linux",
                server_identity.fingerprint(),
            ))
            .unwrap();

        let client = TransportClient::new(&client_identity, client_trust).unwrap();

        // In TLS 1.3 the client's certificate is verified *after* the server's
        // Finished, so the client can believe the handshake succeeded and can
        // even open a stream locally — opening one takes no round trip. The
        // rejection surfaces the moment it tries to exchange data, which is the
        // property that actually matters.
        let refused = match client.connect(addr, &server_identity.dns_name()).await {
            Err(_) => true,
            Ok(conn) => {
                let attempt = async {
                    let mut control = conn.open_control().await?;
                    control.send(&Message::Ping { timestamp: 1 }).await?;
                    control.recv().await
                };
                let outcome =
                    tokio::time::timeout(std::time::Duration::from_secs(3), attempt).await;
                // Either the exchange errored, or it never produced a reply.
                !matches!(outcome, Ok(Ok(_)))
            }
        };

        assert!(
            refused,
            "a client the server has not pinned must be refused"
        );
        client.shutdown();
    }

    /// Pairing mode pins the certificate on first sight, so the connection
    /// succeeds and the fingerprint is remembered for next time.
    /// Pairing mode pins the certificate on first sight so the PIN exchange can
    /// run — but a pin alone is *not* a pairing. The fingerprint stays
    /// unconfirmed until `TrustStore::confirm`, so pairing mode can never be a
    /// blanket "trust anyone who connects while the window is open".
    #[tokio::test]
    async fn test_pairing_mode_pins_provisionally_not_operationally() {
        let identity = DeviceIdentity::generate().unwrap();
        let client_identity = DeviceIdentity::generate().unwrap();

        let server_trust = Arc::new(TrustStore::in_memory());
        server_trust.set_pairing_mode(true);
        let server = TransportServer::start(
            TransportConfig {
                bind_addr: "127.0.0.1:0".parse().unwrap(),
                keep_alive_ms: 5000,
            },
            &identity,
            server_trust,
        )
        .await
        .unwrap();
        let addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            let mut control = conn.accept_control().await.unwrap();
            let _ = control.recv().await;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            server.shutdown();
        });

        let trust = Arc::new(TrustStore::in_memory());
        trust.set_pairing_mode(true);
        let client = TransportClient::new(&client_identity, trust.clone()).unwrap();

        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();
        let mut control = conn.open_control().await.unwrap();
        control.send(&Message::Ping { timestamp: 1 }).await.unwrap();

        // Pinned, so the exchange can proceed…
        assert!(trust.is_pinned_fingerprint(identity.fingerprint()));
        // …but not yet trusted for anything else.
        assert!(!trust.is_trusted_fingerprint(identity.fingerprint()));

        trust
            .confirm(identity.fingerprint(), "peer-server", "Server", "linux")
            .unwrap();
        assert!(trust.is_trusted_fingerprint(identity.fingerprint()));

        conn.close();
        client.shutdown();
        let _ = server_task.await;
    }

    /// Clipboard traffic keeps its order and its sequence numbers advance.
    #[tokio::test]
    async fn test_clipboard_messages_arrive_in_order() {
        let (identity, client_identity, trust, server, addr) = paired_server().await;

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            let mut control = conn.accept_control().await.unwrap();

            let mut seen = Vec::new();
            for _ in 0..5 {
                if let Message::Clipboard { seq, item } = control.recv().await.unwrap() {
                    seen.push((seq, String::from_utf8(item.data).unwrap()));
                }
            }
            conn.close();
            server.shutdown();
            seen
        });

        let client = TransportClient::new(&client_identity, trust).unwrap();
        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();
        let mut control = conn.open_control().await.unwrap();

        for i in 0..5 {
            control
                .send_clipboard(ClipboardItem::from_text(
                    format!("item-{}", i),
                    PeerId::new("p1"),
                ))
                .await
                .unwrap();
        }

        let seen = server_task.await.unwrap();
        assert_eq!(
            seen,
            vec![
                (0, "item-0".to_string()),
                (1, "item-1".to_string()),
                (2, "item-2".to_string()),
                (3, "item-3".to_string()),
                (4, "item-4".to_string()),
            ]
        );

        conn.close();
        client.shutdown();
    }

    /// A replayed clipboard message must be dropped rather than delivered.
    #[tokio::test]
    async fn test_replayed_clipboard_message_is_dropped() {
        let (identity, client_identity, trust, server, addr) = paired_server().await;

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            let mut control = conn.accept_control().await.unwrap();
            // Three messages are sent (seq 5, seq 3 replay, seq 6); the replay
            // must be swallowed so only two surface here.
            let first = control.recv().await.unwrap();
            let second = control.recv().await.unwrap();
            conn.close();
            server.shutdown();
            (first, second)
        });

        let client = TransportClient::new(&client_identity, trust).unwrap();
        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();
        let mut control = conn.open_control().await.unwrap();

        let item = |t: &str| ClipboardItem::from_text(t, PeerId::new("p1"));
        control
            .send(&Message::Clipboard {
                seq: 5,
                item: item("newer"),
            })
            .await
            .unwrap();
        control
            .send(&Message::Clipboard {
                seq: 3,
                item: item("stale-replay"),
            })
            .await
            .unwrap();
        control
            .send(&Message::Clipboard {
                seq: 6,
                item: item("newest"),
            })
            .await
            .unwrap();

        let (first, second) = server_task.await.unwrap();
        match (first, second) {
            (Message::Clipboard { seq: a, item: ia }, Message::Clipboard { seq: b, item: ib }) => {
                assert_eq!((a, b), (5, 6));
                assert_eq!(ia.data, b"newer");
                assert_eq!(ib.data, b"newest");
            }
            other => panic!("expected two clipboard messages, got {:?}", other),
        }

        conn.close();
        client.shutdown();
    }

    #[test]
    fn test_keep_alive_reaches_the_quinn_transport_config() {
        // The F-10 regression: keep_alive_ms was set, defaulted, and asserted in
        // three tests, but never applied — so a paired connection died at
        // quinn's default idle timeout with nothing to reconnect it.
        let config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            keep_alive_ms: 5000,
        };
        assert!(quinn_transport_config(&config).is_ok());

        // Zero disables it rather than producing a zero-length timeout.
        let disabled = TransportConfig {
            keep_alive_ms: 0,
            ..config.clone()
        };
        assert!(quinn_transport_config(&disabled).is_ok());

        // An absurd value is rejected instead of overflowing.
        let absurd = TransportConfig {
            keep_alive_ms: u64::MAX,
            ..config
        };
        assert!(quinn_transport_config(&absurd).is_err());
    }

    /// An idle connection must survive longer than quinn's default, because the
    /// keep-alive now actually reaches the transport config.
    #[tokio::test]
    async fn test_idle_connection_survives_on_keep_alive() {
        let (identity, client_identity, trust, server, addr) = paired_server().await;

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            let mut control = conn.accept_control().await.unwrap();
            let first = control.recv().await;
            // Sit idle, then expect the connection to still be usable.
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
            let second = control.recv().await;
            conn.close();
            server.shutdown();
            (first, second)
        });

        let config = TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            keep_alive_ms: 100,
        };
        let client = TransportClient::with_config(&config, &client_identity, trust).unwrap();
        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();
        let mut control = conn.open_control().await.unwrap();

        control.send(&Message::Ping { timestamp: 1 }).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        control.send(&Message::Ping { timestamp: 2 }).await.unwrap();

        let (first, second) = server_task.await.unwrap();
        assert_eq!(first.unwrap(), Message::Ping { timestamp: 1 });
        assert_eq!(
            second.unwrap(),
            Message::Ping { timestamp: 2 },
            "the connection must survive an idle period"
        );

        conn.close();
        client.shutdown();
    }

    /// A whole transfer over a dedicated stream, with payloads written raw.
    #[tokio::test]
    async fn test_raw_chunk_transfer_round_trips() {
        let (identity, client_identity, trust, server, addr) = paired_server().await;

        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
        let expected = payload.clone();

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            let mut stream = conn.accept_file_stream().await.unwrap();

            let mut buf = Vec::new();
            let mut reassembler: Option<crate::transfer::FileReassembler> = None;
            while let Some(chunk) = recv_chunk_raw(&mut stream, &mut buf).await.unwrap() {
                match reassembler.as_mut() {
                    None => {
                        reassembler = Some(crate::transfer::FileReassembler::new(&chunk).unwrap())
                    }
                    Some(r) => {
                        r.accept(&chunk).unwrap();
                    }
                }
            }

            conn.close();
            server.shutdown();
            reassembler.unwrap().finish().unwrap()
        });

        let client = TransportClient::new(&client_identity, trust).unwrap();
        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();
        let mut stream = conn.open_file_stream().await.unwrap();

        let pieces: Vec<_> = crate::hashing::chunk_and_hash_with_size(&payload, 1024);
        let total = pieces.len() as u32;
        for (index, (data, _)) in pieces.into_iter().enumerate() {
            let chunk = FileChunk::new(
                "tx-raw",
                "blob.bin",
                payload.len() as u64,
                index as u32,
                total,
                data,
            );
            send_chunk_raw(&mut stream, &chunk).await.unwrap();
        }
        stream.finish().unwrap();

        assert_eq!(server_task.await.unwrap(), expected);

        conn.close();
        client.shutdown();
    }

    /// A header claiming a huge payload must not become an allocation.
    #[tokio::test]
    async fn test_raw_chunk_rejects_an_oversized_declared_payload() {
        let (identity, client_identity, trust, server, addr) = paired_server().await;

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            let mut stream = conn.accept_file_stream().await.unwrap();
            let mut buf = Vec::new();
            let result = recv_chunk_raw(&mut stream, &mut buf).await;
            conn.close();
            server.shutdown();
            result
        });

        let client = TransportClient::new(&client_identity, trust).unwrap();
        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();
        let mut stream = conn.open_file_stream().await.unwrap();

        let header = ChunkHeader {
            transfer_id: "tx".into(),
            filename: "lie.bin".into(),
            total_size: u64::MAX,
            chunk_index: 0,
            total_chunks: 1,
            chunk_hash: "00".into(),
            data_len: u32::MAX,
        };
        let encoded = postcard::to_stdvec(&header).unwrap();
        stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&encoded).await.unwrap();
        stream.finish().unwrap();

        let err = server_task.await.unwrap().expect_err("must be rejected");
        assert!(
            err.to_string().contains("payload too large"),
            "unexpected error: {}",
            err
        );

        conn.close();
        client.shutdown();
    }

    /// A dedicated file stream carries a transfer without touching the control
    /// channel, so a large transfer cannot delay clipboard traffic.
    #[tokio::test]
    async fn test_file_stream_is_independent_of_control_channel() {
        let (identity, client_identity, trust, server, addr) = paired_server().await;

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            let mut file = conn.accept_file_stream().await.unwrap();
            let msg = recv_framed(&mut file).await.unwrap();
            conn.close();
            server.shutdown();
            msg
        });

        let client = TransportClient::new(&client_identity, trust).unwrap();
        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();
        let mut file = conn.open_file_stream().await.unwrap();
        let chunk = crate::protocol::FileChunk::new("tx-1", "a.bin", 4, 0, 1, vec![1, 2, 3, 4]);
        send_framed(&mut file, &Message::FileChunk(chunk.clone()))
            .await
            .unwrap();
        file.finish().unwrap();

        assert_eq!(server_task.await.unwrap(), Message::FileChunk(chunk));

        conn.close();
        client.shutdown();
    }

    /// An attacker-supplied length prefix must never become an allocation.
    #[tokio::test]
    async fn test_oversized_frame_is_rejected_before_allocating() {
        let (identity, client_identity, trust, server, addr) = paired_server().await;

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            let mut stream = conn.accept_file_stream().await.unwrap();
            let result = recv_framed(&mut stream).await;
            conn.close();
            server.shutdown();
            result
        });

        let client = TransportClient::new(&client_identity, trust).unwrap();
        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();
        let mut stream = conn.open_file_stream().await.unwrap();
        // Claim a 4 GiB body without sending one.
        stream.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        stream.finish().unwrap();

        let err = server_task.await.unwrap().expect_err("must be rejected");
        assert!(
            err.to_string().contains("Frame too large"),
            "unexpected error: {}",
            err
        );

        conn.close();
        client.shutdown();
    }

    // The audit's point: 16 MiB per stream, times unbounded streams, against a
    // 20 MB total ceiling (INV-01). Enforced at compile time so the ceilings
    // cannot drift back up unnoticed.
    const _: () = {
        assert!(MAX_CONTROL_FRAME_SIZE < 16 * 1024 * 1024);
        assert!(MAX_FILE_FRAME_SIZE < MAX_CONTROL_FRAME_SIZE);
        // A default chunk plus JSON expansion (~3.6x) must still fit.
        assert!(crate::DEFAULT_CHUNK_SIZE * 4 < MAX_FILE_FRAME_SIZE);
        // Concurrent streams times the per-stream ceiling must stay bounded
        // well under the daemon's memory budget.
        assert!(MAX_CONCURRENT_UNI_STREAMS as usize * MAX_FILE_FRAME_SIZE <= 16 * 1024 * 1024);
    };

    #[test]
    fn test_frame_reader_reports_its_limit() {
        let reader = FrameReader::new(1234);
        assert_eq!(reader.limit(), 1234);
        assert!(reader.buf.is_empty(), "no memory reserved before any read");
    }

    /// Frames larger than the ceiling are refused by the sender too, so the
    /// failure is a clear local error rather than a silent drop at the peer.
    #[tokio::test]
    async fn test_sender_refuses_oversized_frame() {
        let (identity, client_identity, trust, server, addr) = paired_server().await;

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            let mut control = conn.accept_control().await.unwrap();
            let _ = control.recv().await;
            server.shutdown();
        });

        let client = TransportClient::new(&client_identity, trust).unwrap();
        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();
        let mut stream = conn.open_file_stream().await.unwrap();

        let huge = crate::protocol::FileChunk::new(
            "tx-1",
            "huge.bin",
            MAX_FILE_FRAME_SIZE as u64 * 2,
            0,
            1,
            vec![0u8; MAX_FILE_FRAME_SIZE],
        );
        let err = send_framed(&mut stream, &Message::FileChunk(huge))
            .await
            .expect_err("oversized frame must be refused");
        assert!(
            err.to_string().contains("Refusing to send"),
            "unexpected error: {}",
            err
        );

        conn.close();
        client.shutdown();
        server_task.abort();
    }

    /// A peer cannot open unbounded streams to multiply the per-stream ceiling.
    #[tokio::test]
    async fn test_concurrent_uni_streams_are_capped() {
        let (identity, client_identity, trust, server, addr) = paired_server().await;

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().expect("no incoming");
            // Accept the connection but never its streams, so none of the
            // peer's opens retire and the cap is what stops it.
            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
            conn.close();
            server.shutdown();
        });

        let client = TransportClient::new(&client_identity, trust).unwrap();
        let conn = client.connect(addr, &identity.dns_name()).await.unwrap();

        let mut opened = 0usize;
        for _ in 0..(MAX_CONCURRENT_UNI_STREAMS as usize + 8) {
            match tokio::time::timeout(
                std::time::Duration::from_millis(80),
                conn.open_file_stream(),
            )
            .await
            {
                Ok(Ok(_stream)) => opened += 1,
                // Either the peer's flow control blocks us (timeout) or the
                // connection refuses — both mean the cap is doing its job.
                _ => break,
            }
        }

        assert!(
            opened <= MAX_CONCURRENT_UNI_STREAMS as usize,
            "opened {} streams, cap is {}",
            opened,
            MAX_CONCURRENT_UNI_STREAMS
        );

        conn.close();
        client.shutdown();
        let _ = server_task.await;
    }
}

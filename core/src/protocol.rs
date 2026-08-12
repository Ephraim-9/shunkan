//! Wire protocol message types for Shunkan P2P communication.
//!
//! The [`Message`] enum is the top-level frame type that wraps all payload
//! variants. Messages are serialized with [`postcard`] and framed with a 4-byte
//! big-endian length prefix.
//!
//! ## Why not JSON
//!
//! `serde_json` renders `Vec<u8>` as a decimal array — `[255,0,17,…]` — so a
//! file chunk or an image cost roughly 3.6 bytes of wire per byte of data, plus
//! parse cost on both ends. That directly contradicted the "full Wi-Fi 6
//! bandwidth" goal and multiplied the memory footprint of every in-flight
//! message. `test_binary_codec_does_not_inflate_binary_payloads` measures it.
//!
//! Postcard is a compact, non-self-describing format: the types survive the
//! swap unchanged, only the encoding differs.
//!
//! For file transfers the payload does not pass through a serializer at all —
//! see [`crate::transport::send_chunk_raw`], which writes a small postcard
//! header followed by the chunk's bytes verbatim.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Unique identifier for a peer on the local network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerId(pub String);

impl PeerId {
    /// Create a new PeerId from a string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a random PeerId.
    pub fn random() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let id: u64 = rng.gen();
        Self(format!("peer-{:016x}", id))
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Information about a peer device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerInfo {
    /// Unique identifier for this peer.
    pub id: PeerId,
    /// Human-readable device name (e.g. "Helliot's ThinkPad").
    pub device_name: String,
    /// Platform identifier (e.g. "linux", "android").
    pub platform: String,
    /// Shunkan core version string.
    pub version: String,
}

impl PeerInfo {
    /// Create a new PeerInfo with the given parameters.
    pub fn new(id: PeerId, device_name: impl Into<String>, platform: impl Into<String>) -> Self {
        Self {
            id,
            device_name: device_name.into(),
            platform: platform.into(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Handshake message exchanged during QUIC connection establishment.
///
/// This carries identity only. It used to also carry a `pin_hash` — an
/// unsalted BLAKE3 of a six-digit PIN, enumerable in milliseconds by anyone who
/// saw one handshake, and read by no code anywhere. PIN authentication is a
/// SPAKE2 exchange now; see [`crate::pairing`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Handshake {
    /// The sender's peer information.
    pub peer_info: PeerInfo,
    /// Timestamp of the handshake (seconds since UNIX epoch).
    pub timestamp: u64,
}

impl Handshake {
    /// Create a new Handshake message.
    pub fn new(peer_info: PeerInfo) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            peer_info,
            timestamp,
        }
    }
}

/// Type of content in a clipboard item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContentType {
    /// Plain text content.
    PlainText,
    /// Rich text (HTML) content.
    RichText,
    /// Image data (PNG bytes).
    Image,
    /// A file URI or path.
    FileUri,
}

/// A clipboard item to be synchronized between peers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClipboardItem {
    /// BLAKE3 hash of the content for deduplication.
    pub content_hash: String,
    /// The type of content.
    pub content_type: ContentType,
    /// The raw content bytes (UTF-8 text or binary).
    pub data: Vec<u8>,
    /// Timestamp when the item was copied (seconds since UNIX epoch).
    pub timestamp: u64,
    /// The peer that originated this clipboard item.
    pub source_peer: PeerId,
}

impl ClipboardItem {
    /// Create a new ClipboardItem with automatic BLAKE3 hashing and timestamp.
    pub fn new(content_type: ContentType, data: Vec<u8>, source_peer: PeerId) -> Self {
        let content_hash = crate::hashing::hash_bytes(&data);
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            content_hash,
            content_type,
            data,
            timestamp,
            source_peer,
        }
    }

    /// Create a text clipboard item from a string.
    pub fn from_text(text: impl Into<String>, source_peer: PeerId) -> Self {
        Self::new(
            ContentType::PlainText,
            text.into().into_bytes(),
            source_peer,
        )
    }
}

/// A chunk of file data being transferred.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileChunk {
    /// Unique identifier for the file transfer session.
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
    /// The chunk data bytes.
    pub data: Vec<u8>,
}

impl FileChunk {
    /// Create a new FileChunk with automatic BLAKE3 hashing.
    pub fn new(
        transfer_id: impl Into<String>,
        filename: impl Into<String>,
        total_size: u64,
        chunk_index: u32,
        total_chunks: u32,
        data: Vec<u8>,
    ) -> Self {
        let chunk_hash = crate::hashing::hash_bytes(&data);
        Self {
            transfer_id: transfer_id.into(),
            filename: filename.into(),
            total_size,
            chunk_index,
            total_chunks,
            chunk_hash,
            data,
        }
    }

    /// Verify the integrity of this chunk's data against its stored BLAKE3 hash.
    pub fn verify(&self) -> bool {
        let computed = crate::hashing::hash_bytes(&self.data);
        computed == self.chunk_hash
    }
}

/// Transfer completion acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransferAck {
    /// The transfer session ID being acknowledged.
    pub transfer_id: String,
    /// Whether the transfer completed successfully.
    pub success: bool,
    /// Optional error message if the transfer failed.
    pub error: Option<String>,
}

/// Top-level wire protocol message envelope.
///
/// All messages are serialized with postcard and framed with a 4-byte big-endian
/// length prefix when sent over QUIC streams.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Message {
    /// Initial handshake message for pairing.
    Handshake(Handshake),
    /// Clipboard item synchronization.
    ///
    /// `seq` is a per-connection monotonic counter assigned by the sender.
    /// Clipboard traffic travels on a single ordered stream, so this is a
    /// belt-and-braces check rather than the primary ordering mechanism — but
    /// it also survives a reconnect, where stream ordering does not.
    Clipboard {
        /// Sender-assigned monotonic sequence number.
        seq: u64,
        /// The clipboard item being synchronized.
        item: ClipboardItem,
    },
    /// File chunk transfer.
    FileChunk(FileChunk),
    /// Transfer acknowledgment.
    Ack(TransferAck),
    /// One side's SPAKE2 message in the PIN pairing exchange.
    ///
    /// Both sides send this simultaneously; SPAKE2 is one round.
    PairingHello {
        /// The opaque SPAKE2 element. Reveals nothing about the PIN.
        spake: Vec<u8>,
    },
    /// Key confirmation, proving the sender derived the same key and saw the
    /// same pair of TLS certificate fingerprints.
    PairingConfirm {
        /// Hex-encoded keyed BLAKE3 MAC over the channel binding.
        mac: String,
    },
    /// The outcome of a pairing exchange, so the peer learns why it failed.
    PairingResult {
        /// Whether this side accepted the pairing.
        accepted: bool,
        /// Human-readable reason when rejected.
        reason: Option<String>,
    },
    /// Ping for keepalive.
    Ping { timestamp: u64 },
    /// Pong response to a ping.
    Pong { timestamp: u64 },
}

impl Message {
    /// Serialize this message to postcard bytes.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        postcard::to_stdvec(self).map_err(|e| anyhow::anyhow!("Failed to encode message: {}", e))
    }

    /// Deserialize a message from postcard bytes.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        postcard::from_bytes(bytes).map_err(|e| anyhow::anyhow!("Failed to decode message: {}", e))
    }

    /// Serialize with a 4-byte big-endian length prefix for framing.
    pub fn to_framed_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let body = self.to_bytes()?;
        let len = u32::try_from(body.len()).map_err(|_| {
            anyhow::anyhow!("Message of {} bytes exceeds the frame prefix", body.len())
        })?;

        let mut buf = Vec::with_capacity(4 + body.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&body);
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_creation() {
        let id = PeerId::new("test-peer");
        assert_eq!(id.0, "test-peer");
        assert_eq!(id.to_string(), "test-peer");
    }

    #[test]
    fn test_peer_id_random() {
        let id1 = PeerId::random();
        let id2 = PeerId::random();
        assert_ne!(id1, id2);
        assert!(id1.0.starts_with("peer-"));
    }

    #[test]
    fn test_peer_info() {
        let peer = PeerInfo::new(PeerId::new("p1"), "TestDevice", "linux");
        assert_eq!(peer.device_name, "TestDevice");
        assert_eq!(peer.platform, "linux");
        assert_eq!(peer.version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn test_handshake_creation() {
        let peer = PeerInfo::new(PeerId::new("p1"), "Dev", "linux");
        let hs = Handshake::new(peer.clone());
        assert_eq!(hs.peer_info, peer);
        assert!(hs.timestamp > 0);
    }

    #[test]
    fn test_handshake_carries_no_pin_material() {
        let peer = PeerInfo::new(PeerId::new("p1"), "Dev", "linux");
        let encoded = Message::Handshake(Handshake::new(peer)).to_bytes().unwrap();
        assert!(
            !encoded.windows(3).any(|w| w == b"pin"),
            "the handshake must not carry PIN material"
        );
    }

    /// The F-20 measurement. JSON rendered `Vec<u8>` as a decimal array, so a
    /// 64 KiB chunk cost ~235 KiB on the wire — 3.57x, against a "full Wi-Fi 6
    /// bandwidth" goal.
    #[test]
    fn test_binary_codec_does_not_inflate_binary_payloads() {
        let payload: Vec<u8> = (0..crate::DEFAULT_CHUNK_SIZE)
            .map(|i| (i % 256) as u8)
            .collect();
        let raw_len = payload.len();

        let msg = Message::FileChunk(FileChunk::new(
            "tx-1",
            "photo.raw",
            raw_len as u64,
            0,
            1,
            payload,
        ));

        let postcard_len = msg.to_bytes().unwrap().len();
        let json_len = serde_json::to_vec(&msg).unwrap().len();

        // What we replaced.
        assert!(
            json_len as f64 / raw_len as f64 > 3.0,
            "JSON expansion was {:.2}x",
            json_len as f64 / raw_len as f64
        );

        // What we ship: near-zero overhead over the raw bytes.
        let expansion = postcard_len as f64 / raw_len as f64;
        assert!(
            expansion < 1.02,
            "postcard expansion was {:.4}x ({} bytes for {} raw)",
            expansion,
            postcard_len,
            raw_len
        );
    }

    #[test]
    fn test_binary_codec_round_trips_every_variant() {
        let peer = PeerInfo::new(PeerId::new("p1"), "Dev", "linux");
        let messages = vec![
            Message::Handshake(Handshake::new(peer)),
            Message::Clipboard {
                seq: u64::MAX,
                item: ClipboardItem::new(
                    ContentType::Image,
                    vec![0x00, 0xFF, 0x7F, 0x80],
                    PeerId::new("p"),
                ),
            },
            Message::FileChunk(FileChunk::new("tx", "f.bin", 3, 0, 1, vec![0, 255, 128])),
            Message::Ack(TransferAck {
                transfer_id: "tx".into(),
                success: false,
                error: Some("nope".into()),
            }),
            Message::PairingHello {
                spake: vec![1, 2, 3],
            },
            Message::PairingConfirm { mac: "ab".into() },
            Message::PairingResult {
                accepted: true,
                reason: None,
            },
            Message::Ping { timestamp: 0 },
            Message::Pong {
                timestamp: u64::MAX,
            },
        ];

        for msg in messages {
            let decoded = Message::from_bytes(&msg.to_bytes().unwrap()).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_truncated_frame_is_rejected_rather_than_misread() {
        let msg = Message::Clipboard {
            seq: 1,
            item: ClipboardItem::from_text("hello", PeerId::new("p")),
        };
        let bytes = msg.to_bytes().unwrap();
        assert!(Message::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(Message::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_pairing_messages_round_trip() {
        let messages = vec![
            Message::PairingHello {
                spake: vec![1, 2, 3, 4],
            },
            Message::PairingConfirm {
                mac: "deadbeef".into(),
            },
            Message::PairingResult {
                accepted: false,
                reason: Some("wrong PIN".into()),
            },
            Message::PairingResult {
                accepted: true,
                reason: None,
            },
        ];

        for msg in messages {
            let decoded = Message::from_bytes(&msg.to_bytes().unwrap()).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_clipboard_item_from_text() {
        let item = ClipboardItem::from_text("hello world", PeerId::new("p1"));
        assert_eq!(item.content_type, ContentType::PlainText);
        assert_eq!(item.data, b"hello world");
        assert!(!item.content_hash.is_empty());
        assert!(item.timestamp > 0);
    }

    #[test]
    fn test_clipboard_item_dedup_hash() {
        let item1 = ClipboardItem::from_text("same content", PeerId::new("p1"));
        let item2 = ClipboardItem::from_text("same content", PeerId::new("p2"));
        // Same content should produce the same BLAKE3 hash regardless of source.
        assert_eq!(item1.content_hash, item2.content_hash);
    }

    #[test]
    fn test_clipboard_item_different_hash() {
        let item1 = ClipboardItem::from_text("content a", PeerId::new("p1"));
        let item2 = ClipboardItem::from_text("content b", PeerId::new("p1"));
        assert_ne!(item1.content_hash, item2.content_hash);
    }

    #[test]
    fn test_file_chunk_creation_and_verify() {
        let chunk = FileChunk::new("tx-1", "photo.jpg", 128000, 0, 2, vec![1, 2, 3, 4]);
        assert_eq!(chunk.transfer_id, "tx-1");
        assert_eq!(chunk.filename, "photo.jpg");
        assert_eq!(chunk.chunk_index, 0);
        assert_eq!(chunk.total_chunks, 2);
        assert!(chunk.verify());
    }

    #[test]
    fn test_file_chunk_tampered_data_fails_verify() {
        let mut chunk = FileChunk::new("tx-1", "photo.jpg", 128000, 0, 2, vec![1, 2, 3, 4]);
        chunk.data = vec![5, 6, 7, 8]; // tamper
        assert!(!chunk.verify());
    }

    #[test]
    fn test_message_serialization_roundtrip() {
        let peer = PeerInfo::new(PeerId::new("p1"), "Dev", "linux");
        let hs = Handshake::new(peer);
        let msg = Message::Handshake(hs.clone());

        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_message_framed_bytes() {
        let msg = Message::Ping { timestamp: 12345 };
        let framed = msg.to_framed_bytes().unwrap();
        // First 4 bytes are length prefix
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(len, framed.len() - 4);
        let decoded = Message::from_bytes(&framed[4..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_all_message_variants_serialize() {
        let peer = PeerInfo::new(PeerId::new("p1"), "Dev", "linux");
        let messages = vec![
            Message::Handshake(Handshake::new(peer)),
            Message::Clipboard {
                seq: 7,
                item: ClipboardItem::from_text("test", PeerId::new("p1")),
            },
            Message::FileChunk(FileChunk::new("tx", "f.bin", 100, 0, 1, vec![0xFF])),
            Message::Ack(TransferAck {
                transfer_id: "tx".into(),
                success: true,
                error: None,
            }),
            Message::Ping { timestamp: 1 },
            Message::Pong { timestamp: 1 },
        ];

        for msg in messages {
            let bytes = msg.to_bytes().unwrap();
            let decoded = Message::from_bytes(&bytes).unwrap();
            assert_eq!(msg, decoded);
        }
    }

    #[test]
    fn test_transfer_ack() {
        let ack = TransferAck {
            transfer_id: "tx-42".into(),
            success: false,
            error: Some("checksum mismatch".into()),
        };
        let msg = Message::Ack(ack.clone());
        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        if let Message::Ack(decoded_ack) = decoded {
            assert_eq!(decoded_ack, ack);
        } else {
            panic!("Expected Ack variant");
        }
    }
}

//! Integration tests for shunkan-core.
//!
//! These tests verify cross-module interactions and end-to-end workflows.

use shunkan_core::hashing;
use shunkan_core::history::ClipboardHistory;
use shunkan_core::protocol::*;
use shunkan_core::crypto::PairingPin;

/// Test the full clipboard workflow: create item → hash → store → retrieve → search.
#[test]
fn test_clipboard_workflow() {
    let mut history = ClipboardHistory::new(50);
    let peer = PeerId::new("desktop-linux");

    // Simulate copying text
    let item1 = ClipboardItem::from_text("password123", peer.clone());
    let item2 = ClipboardItem::from_text("https://example.com", peer.clone());
    let item3 = ClipboardItem::from_text("Hello World", peer.clone());

    assert!(history.push(item1));
    assert!(history.push(item2));
    assert!(history.push(item3));
    assert_eq!(history.len(), 3);

    // Search should find the URL
    let results = history.search("example");
    assert_eq!(results.len(), 1);
    assert_eq!(
        String::from_utf8_lossy(&results[0].data),
        "https://example.com"
    );

    // Latest should be the most recent
    assert_eq!(
        String::from_utf8_lossy(&history.latest().unwrap().data),
        "Hello World"
    );
}

/// Test file chunking and integrity verification end-to-end.
#[test]
fn test_file_transfer_integrity() {
    // Simulate a file
    let file_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

    // Chunk the file
    let chunks = hashing::chunk_and_hash_with_size(&file_data, 100);
    assert_eq!(chunks.len(), 10);

    // Create FileChunk protocol messages
    let file_chunks: Vec<FileChunk> = chunks
        .iter()
        .enumerate()
        .map(|(i, (data, _hash))| {
            FileChunk::new(
                "transfer-001",
                "testfile.bin",
                file_data.len() as u64,
                i as u32,
                chunks.len() as u32,
                data.clone(),
            )
        })
        .collect();

    // Verify each chunk
    for chunk in &file_chunks {
        assert!(chunk.verify(), "Chunk {} failed verification", chunk.chunk_index);
    }

    // Reassemble and verify full file integrity
    let mut reassembled = Vec::new();
    for chunk in &file_chunks {
        reassembled.extend_from_slice(&chunk.data);
    }
    assert_eq!(reassembled, file_data);

    // Verify overall hash
    let original_hash = hashing::hash_bytes(&file_data);
    let reassembled_hash = hashing::hash_bytes(&reassembled);
    assert_eq!(original_hash, reassembled_hash);
}

/// Test message serialization roundtrip for all variants.
#[test]
fn test_protocol_serialization_roundtrip() {
    let peer = PeerInfo::new(PeerId::new("test"), "TestDevice", "linux");

    let messages = vec![
        Message::Handshake(Handshake::new(peer, Some("pinhash".into()))),
        Message::Clipboard(ClipboardItem::from_text("clipboard data", PeerId::new("p1"))),
        Message::FileChunk(FileChunk::new("tx1", "file.txt", 500, 0, 1, vec![1, 2, 3])),
        Message::Ack(TransferAck {
            transfer_id: "tx1".into(),
            success: true,
            error: None,
        }),
        Message::Ping { timestamp: 1234567890 },
        Message::Pong { timestamp: 1234567890 },
    ];

    for original in &messages {
        // Serialize
        let bytes = original.to_bytes().unwrap();
        // Deserialize
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(original, &decoded);

        // Also test framed encoding
        let framed = original.to_framed_bytes().unwrap();
        let len = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(len + 4, framed.len());
        let decoded_framed = Message::from_bytes(&framed[4..]).unwrap();
        assert_eq!(original, &decoded_framed);
    }
}

/// Test PIN pairing workflow.
#[test]
fn test_pairing_workflow() {
    // Device A generates a PIN and displays it
    let pin_a = PairingPin::generate();
    let pin_str = pin_a.as_str().to_string();
    let pin_hash = pin_a.hash();

    // Device B reads the PIN from the user
    let pin_b = PairingPin::from_str(&pin_str).unwrap();

    // Device B computes its hash and sends it
    let pin_b_hash = pin_b.hash();

    // They should match
    assert_eq!(pin_hash, pin_b_hash);
    assert!(pin_a.verify_hash(&pin_b_hash));
    assert!(pin_b.verify_hash(&pin_hash));
}

/// Test deduplication across clipboard sync.
#[test]
fn test_cross_peer_deduplication() {
    let mut history = ClipboardHistory::new(50);

    // Same text from different peers should deduplicate
    let item_linux = ClipboardItem::from_text("shared text", PeerId::new("linux-desktop"));
    let item_android = ClipboardItem::from_text("shared text", PeerId::new("android-phone"));

    assert!(history.push(item_linux));
    assert!(!history.push(item_android)); // duplicate content
    assert_eq!(history.len(), 1);
}

/// Test stream hasher matches chunk-based hashing.
#[test]
fn test_stream_vs_chunk_hash_consistency() {
    let data: Vec<u8> = (0..500).map(|i| (i * 7 % 256) as u8).collect();

    // Full hash
    let full_hash = hashing::hash_bytes(&data);

    // Stream hash
    let mut stream = hashing::StreamHasher::new();
    for chunk in data.chunks(64) {
        stream.update(chunk);
    }
    let stream_hash = stream.finalize_hex();

    assert_eq!(full_hash, stream_hash);
}

/// Test that BLAKE3 is used (not SHA-256) — INV-05 compliance.
#[test]
fn test_blake3_not_sha256() {
    // Known BLAKE3 hash of "shunkan" — this verifies we're actually using BLAKE3
    let hash = hashing::hash_bytes(b"shunkan");
    // BLAKE3 hash should be 64 hex chars
    assert_eq!(hash.len(), 64);

    // Verify it matches blake3 crate directly
    let expected = blake3::hash(b"shunkan").to_hex().to_string();
    assert_eq!(hash, expected);
}

/// Test merkle root for file transfer verification.
#[test]
fn test_merkle_root_verification() {
    let data = vec![0u8; 300];
    let chunks = hashing::chunk_and_hash_with_size(&data, 100);

    let chunk_hashes: Vec<String> = chunks.iter().map(|(_, h)| h.clone()).collect();
    let root1 = hashing::compute_merkle_root(&chunk_hashes);

    // Same data should produce the same merkle root
    let chunks2 = hashing::chunk_and_hash_with_size(&data, 100);
    let chunk_hashes2: Vec<String> = chunks2.iter().map(|(_, h)| h.clone()).collect();
    let root2 = hashing::compute_merkle_root(&chunk_hashes2);

    assert_eq!(root1, root2);

    // Different data should produce a different root
    let data3 = vec![1u8; 300];
    let chunks3 = hashing::chunk_and_hash_with_size(&data3, 100);
    let chunk_hashes3: Vec<String> = chunks3.iter().map(|(_, h)| h.clone()).collect();
    let root3 = hashing::compute_merkle_root(&chunk_hashes3);

    assert_ne!(root1, root3);
}

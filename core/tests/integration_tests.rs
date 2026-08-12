//! Integration tests for shunkan-core.
//!
//! These tests verify cross-module interactions and end-to-end workflows.

use shunkan_core::crypto::PairingPin;
use shunkan_core::hashing;
use shunkan_core::history::ClipboardHistory;
use shunkan_core::identity::DeviceIdentity;
use shunkan_core::pairing::{ChannelBinding, PairingRole, PairingSession};
use shunkan_core::protocol::*;
use shunkan_core::transfer::FileReassembler;
use shunkan_core::transport::{TransportClient, TransportConfig, TransportServer};
use shunkan_core::trust::{PairedPeer, TrustStore};
use std::sync::Arc;
use std::time::Duration;

/// Two devices, two endpoints, one clipboard item — driven entirely through the
/// public API, with no hand-built TLS configuration anywhere.
///
/// This is the test the audit asked for: the one that would have caught the
/// transport being unable to connect, the daemon never calling the core, and
/// per-message stream ordering, all at once. If it passes, a link works.
#[tokio::test]
async fn test_two_devices_sync_a_clipboard_item_end_to_end() {
    // ── Device A (listener) and device B (dialer), each with its own identity
    let device_a = DeviceIdentity::generate().unwrap();
    let device_b = DeviceIdentity::generate().unwrap();

    // ── They have paired: each has pinned the other's certificate fingerprint
    let trust_a = Arc::new(TrustStore::in_memory());
    trust_a
        .pair(PairedPeer::new(
            device_b.peer_id().0.clone(),
            "Device B",
            "linux",
            device_b.fingerprint(),
        ))
        .unwrap();

    let trust_b = Arc::new(TrustStore::in_memory());
    trust_b
        .pair(PairedPeer::new(
            device_a.peer_id().0.clone(),
            "Device A",
            "linux",
            device_a.fingerprint(),
        ))
        .unwrap();

    // ── Device A listens
    let server = TransportServer::start(
        TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..TransportConfig::default()
        },
        &device_a,
        trust_a.clone(),
    )
    .await
    .unwrap();
    let server_addr = server.local_addr().unwrap();

    let a_peer_info = PeerInfo::new(device_a.peer_id().clone(), "Device A", "linux");
    let b_peer_info = PeerInfo::new(device_b.peer_id().clone(), "Device B", "linux");

    let a_info_for_task = a_peer_info.clone();
    let listener = tokio::spawn(async move {
        let conn = server
            .accept()
            .await
            .unwrap()
            .expect("no incoming connection");
        let mut control = conn.accept_control().await.unwrap();

        // Handshake exchange
        control
            .send(&Message::Handshake(Handshake::new(a_info_for_task)))
            .await
            .unwrap();
        let peer_info = match control.recv().await.unwrap() {
            Message::Handshake(hs) => hs.peer_info,
            other => panic!("expected handshake, got {:?}", other),
        };

        // Apply inbound clipboard items to a real history store
        let mut history = ClipboardHistory::new(10);
        for _ in 0..2 {
            match control.recv().await.unwrap() {
                Message::Clipboard { item, .. } => {
                    history.push(item);
                }
                other => panic!("expected clipboard, got {:?}", other),
            }
        }

        let received: Vec<String> = history
            .items()
            .map(|i| String::from_utf8_lossy(&i.data).to_string())
            .collect();

        tokio::time::sleep(Duration::from_millis(100)).await;
        conn.close();
        server.shutdown();
        (peer_info, received)
    });

    // ── Device B dials
    let client = TransportClient::new(&device_b, trust_b).unwrap();
    let conn = client
        .connect(server_addr, &device_a.dns_name())
        .await
        .expect("paired devices must be able to connect");

    let mut control = conn.open_control().await.unwrap();
    control
        .send(&Message::Handshake(Handshake::new(b_peer_info.clone())))
        .await
        .unwrap();

    let seen_a = match control.recv().await.unwrap() {
        Message::Handshake(hs) => hs.peer_info,
        other => panic!("expected handshake, got {:?}", other),
    };
    assert_eq!(seen_a, a_peer_info, "device B must identify device A");

    control
        .send_clipboard(ClipboardItem::from_text(
            "otp: 314159",
            device_b.peer_id().clone(),
        ))
        .await
        .unwrap();
    control
        .send_clipboard(ClipboardItem::from_text(
            "https://example.com/second",
            device_b.peer_id().clone(),
        ))
        .await
        .unwrap();

    let (seen_b, received) = listener.await.unwrap();

    assert_eq!(seen_b, b_peer_info, "device A must identify device B");
    assert_eq!(
        received,
        vec![
            "https://example.com/second".to_string(),
            "otp: 314159".to_string(),
        ],
        "items must arrive in order, newest at the front of history"
    );
    assert!(trust_a.is_trusted_fingerprint(device_b.fingerprint()));

    conn.close();
    client.shutdown();
}

/// An unpaired device on the same network must not be able to connect at all.
#[tokio::test]
async fn test_unpaired_device_is_refused() {
    let device_a = DeviceIdentity::generate().unwrap();

    let server = TransportServer::start(
        TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..TransportConfig::default()
        },
        &device_a,
        Arc::new(TrustStore::in_memory()),
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.accept().await;
    });

    // An empty trust store with pairing mode off — a stranger on café Wi-Fi.
    let stranger_identity = DeviceIdentity::generate().unwrap();
    let stranger =
        TransportClient::new(&stranger_identity, Arc::new(TrustStore::in_memory())).unwrap();
    let result = stranger.connect(addr, &device_a.dns_name()).await;

    assert!(
        result.is_err(),
        "an unpaired device must not establish a connection"
    );
    stranger.shutdown();
}

/// A device that restarts keeps its identity, so a paired peer still trusts it.
#[test]
fn test_restart_preserves_pairing() {
    let dir = std::env::temp_dir().join(format!("shunkan-e2e-restart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let first_boot = DeviceIdentity::load_or_create(&dir).unwrap();

    let peer_trust = TrustStore::in_memory();
    peer_trust
        .pair(PairedPeer::new(
            first_boot.peer_id().0.clone(),
            "Device",
            "linux",
            first_boot.fingerprint(),
        ))
        .unwrap();

    // Restart: same directory, same device.
    let second_boot = DeviceIdentity::load_or_create(&dir).unwrap();

    assert_eq!(first_boot.peer_id(), second_boot.peer_id());
    assert!(
        peer_trust.is_trusted_fingerprint(second_boot.fingerprint()),
        "a restarted device must not look like a stranger"
    );

    std::fs::remove_dir_all(&dir).ok();
}

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
        assert!(
            chunk.verify(),
            "Chunk {} failed verification",
            chunk.chunk_index
        );
    }

    // Reassemble through the real reassembly path, shuffled to prove it does
    // not depend on arrival order.
    let mut shuffled: Vec<&FileChunk> = file_chunks.iter().collect();
    shuffled.rotate_left(4);
    shuffled.reverse();

    let mut reassembler = FileReassembler::new(shuffled[0]).unwrap();
    let mut complete = reassembler.is_complete();
    for chunk in &shuffled[1..] {
        complete = reassembler.accept(chunk).unwrap();
    }
    assert!(complete, "every chunk was delivered");

    let reassembled = reassembler.finish().unwrap();
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
        Message::Handshake(Handshake::new(peer)),
        Message::Clipboard {
            seq: 3,
            item: ClipboardItem::from_text("clipboard data", PeerId::new("p1")),
        },
        Message::FileChunk(FileChunk::new("tx1", "file.txt", 500, 0, 1, vec![1, 2, 3])),
        Message::Ack(TransferAck {
            transfer_id: "tx1".into(),
            success: true,
            error: None,
        }),
        Message::Ping {
            timestamp: 1234567890,
        },
        Message::Pong {
            timestamp: 1234567890,
        },
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

/// The full PIN pairing workflow, end to end over a real QUIC connection.
///
/// Two devices that have never met complete a SPAKE2 exchange over the channel,
/// confirm it against both TLS certificate fingerprints, and end up
/// operationally trusting each other. The PIN never reaches the wire.
#[tokio::test]
async fn test_pin_pairing_promotes_strangers_to_trusted_peers() {
    let device_a = DeviceIdentity::generate().unwrap();
    let device_b = DeviceIdentity::generate().unwrap();

    // Device A shows a PIN; the user types it into device B.
    let pin_a = PairingPin::generate();
    let pin_b = PairingPin::parse(pin_a.as_str()).unwrap();

    // Neither device knows the other. Both open a pairing window.
    let trust_a = Arc::new(TrustStore::in_memory());
    trust_a.set_pairing_mode(true);
    let trust_b = Arc::new(TrustStore::in_memory());
    trust_b.set_pairing_mode(true);

    let server = TransportServer::start(
        TransportConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            ..TransportConfig::default()
        },
        &device_a,
        trust_a.clone(),
    )
    .await
    .unwrap();
    let addr = server.local_addr().unwrap();

    let a_id = device_a.peer_id().0.clone();
    let b_id = device_b.peer_id().0.clone();
    let a_fp = device_a.fingerprint().to_string();
    let b_fp = device_b.fingerprint().to_string();
    let a_fp_for_task = a_fp.clone();

    // Device A: the listener, so the SPAKE2 responder.
    let (responder_a_id, responder_b_id) = (b_id.clone(), a_id.clone());
    let listener_task = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().expect("no incoming");
        let peer_fp = conn.peer_fingerprint().expect("mutual TLS gives us a cert");
        let mut control = conn.accept_control().await.unwrap();

        let session = PairingSession::start(
            &pin_a,
            PairingRole::Responder,
            &responder_a_id,
            &responder_b_id,
            ChannelBinding::new(PairingRole::Responder, &a_fp_for_task, &peer_fp),
        );
        control
            .send(&Message::PairingHello {
                spake: session.outbound_message().to_vec(),
            })
            .await
            .unwrap();

        let peer_spake = match control.recv().await.unwrap() {
            Message::PairingHello { spake } => spake,
            other => panic!("expected PairingHello, got {:?}", other),
        };
        let confirmation = session.finish(&peer_spake).unwrap();

        control
            .send(&Message::PairingConfirm {
                mac: confirmation.our_mac(),
            })
            .await
            .unwrap();
        let peer_mac = match control.recv().await.unwrap() {
            Message::PairingConfirm { mac } => mac,
            other => panic!("expected PairingConfirm, got {:?}", other),
        };

        let ok = confirmation.verify_peer_mac(&peer_mac);
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn.close();
        server.shutdown();
        (ok, peer_fp)
    });

    // Device B: the dialer, so the SPAKE2 initiator.
    let client = TransportClient::new(&device_b, trust_b.clone()).unwrap();
    let conn = client.connect(addr, &device_a.dns_name()).await.unwrap();
    let peer_fp = conn.peer_fingerprint().expect("server cert");
    let mut control = conn.open_control().await.unwrap();

    let session = PairingSession::start(
        &pin_b,
        PairingRole::Initiator,
        &b_id,
        &a_id,
        ChannelBinding::new(PairingRole::Initiator, &b_fp, &peer_fp),
    );
    control
        .send(&Message::PairingHello {
            spake: session.outbound_message().to_vec(),
        })
        .await
        .unwrap();

    let peer_spake = match control.recv().await.unwrap() {
        Message::PairingHello { spake } => spake,
        other => panic!("expected PairingHello, got {:?}", other),
    };
    let confirmation = session.finish(&peer_spake).unwrap();

    let peer_mac = match control.recv().await.unwrap() {
        Message::PairingConfirm { mac } => mac,
        other => panic!("expected PairingConfirm, got {:?}", other),
    };
    control
        .send(&Message::PairingConfirm {
            mac: confirmation.our_mac(),
        })
        .await
        .unwrap();

    assert!(
        confirmation.verify_peer_mac(&peer_mac),
        "device B must confirm device A"
    );

    let (listener_ok, b_fp_seen_by_a) = listener_task.await.unwrap();
    assert!(listener_ok, "device A must confirm device B");
    assert_eq!(b_fp_seen_by_a, b_fp, "mutual TLS identifies the dialer too");

    // Confirming the pairing is what makes each device operationally trusted.
    assert!(!trust_b.is_trusted_fingerprint(&a_fp), "not yet confirmed");
    trust_b.confirm(&a_fp, &a_id, "Device A", "linux").unwrap();
    trust_a.confirm(&b_fp, &b_id, "Device B", "linux").unwrap();

    assert!(trust_b.is_trusted_fingerprint(&a_fp));
    assert!(trust_a.is_trusted_fingerprint(&b_fp));

    conn.close();
    client.shutdown();
}

/// A wrong PIN must not produce a pairing, even though the TLS channel is fine.
#[test]
fn test_wrong_pin_does_not_confirm() {
    let a_fp = "aaaa".repeat(16);
    let b_fp = "bbbb".repeat(16);

    let right = PairingPin::parse("123456").unwrap();
    let wrong = PairingPin::parse("654321").unwrap();

    let a = PairingSession::start(
        &right,
        PairingRole::Initiator,
        "peer-a",
        "peer-b",
        ChannelBinding::new(PairingRole::Initiator, &a_fp, &b_fp),
    );
    let b = PairingSession::start(
        &wrong,
        PairingRole::Responder,
        "peer-a",
        "peer-b",
        ChannelBinding::new(PairingRole::Responder, &b_fp, &a_fp),
    );

    let msg_a = a.outbound_message().to_vec();
    let msg_b = b.outbound_message().to_vec();

    // SPAKE2 rejecting outright is an equally good outcome; if it does produce
    // keys, they must not confirm against each other.
    if let (Ok(conf_a), Ok(conf_b)) = (a.finish(&msg_b), b.finish(&msg_a)) {
        assert!(!conf_a.verify_peer_mac(&conf_b.our_mac()));
        assert!(!conf_b.verify_peer_mac(&conf_a.our_mac()));
    }
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

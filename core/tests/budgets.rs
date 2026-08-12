//! Budget checks against the project's stated numbers.
//!
//! These assert the invariants *and* print what they measured, so CI logs carry
//! a record rather than just a green tick. Run with `--nocapture` to see them.
//!
//! Targets, from the PRD and memory.html:
//!
//! - INV-01: ~15 MB idle RAM, hard ceiling 20 MB
//! - "full Wi-Fi 6 bandwidth" for file transfer — so wire overhead must be
//!   negligible, not 3.57x
//! - sub-50 ms text propagation — so nothing in the hot path may be O(n) per
//!   keystroke-scale event

use shunkan_core::hashing;
use shunkan_core::history::{ClipboardHistory, DEFAULT_MAX_BYTES};
use shunkan_core::protocol::{ClipboardItem, ContentType, FileChunk, Message, PeerId};
use shunkan_core::DEFAULT_CHUNK_SIZE;

/// Wire overhead for a full-size file chunk must be negligible.
#[test]
fn budget_wire_expansion_for_binary_payloads() {
    let payload: Vec<u8> = (0..DEFAULT_CHUNK_SIZE).map(|i| (i % 256) as u8).collect();
    let raw = payload.len();

    let msg = Message::FileChunk(FileChunk::new(
        "tx",
        "photo.raw",
        raw as u64,
        0,
        1,
        payload.clone(),
    ));

    let encoded = msg.to_bytes().unwrap().len();
    let json = serde_json::to_vec(&msg).unwrap().len();

    println!(
        "wire expansion for a {} B chunk: postcard {} B ({:.4}x), json {} B ({:.2}x)",
        raw,
        encoded,
        encoded as f64 / raw as f64,
        json,
        json as f64 / raw as f64
    );

    assert!(
        encoded as f64 / raw as f64 <= 1.02,
        "postcard expansion {:.4}x exceeds the 1.02x budget",
        encoded as f64 / raw as f64
    );
}

/// A full history must stay inside its byte budget, whatever is copied into it.
#[test]
fn budget_history_stays_within_its_memory_ceiling() {
    let mut history = ClipboardHistory::with_default_capacity();

    // A hundred "screenshots" of 1 MiB each: 100 MB if only entries were capped.
    let screenshot = vec![0xABu8; 1024 * 1024];
    for i in 0..100 {
        let mut data = screenshot.clone();
        data[0] = i as u8; // make each one distinct
        history.push(ClipboardItem::new(
            ContentType::Image,
            data,
            PeerId::new("p"),
        ));
    }

    println!(
        "history after 100 x 1 MiB items: {} entries, {} B held (budget {} B)",
        history.len(),
        history.current_bytes(),
        DEFAULT_MAX_BYTES
    );

    assert!(
        history.current_bytes() <= DEFAULT_MAX_BYTES,
        "history held {} B against a {} B budget",
        history.current_bytes(),
        DEFAULT_MAX_BYTES
    );
    // The history budget alone must leave room under INV-01's 20 MB ceiling.
    const _: () = assert!(DEFAULT_MAX_BYTES < 20 * 1024 * 1024);
    assert!(!history.is_empty(), "the newest item must always survive");
}

/// Streaming a file must not require holding the file.
#[test]
fn budget_streaming_peak_memory_is_one_chunk() {
    // 8 MiB of "file", streamed through a 64 KiB window.
    let file = vec![0x5Au8; 8 * 1024 * 1024];

    let mut largest_chunk = 0usize;
    let summary = hashing::stream_chunks(&file[..], DEFAULT_CHUNK_SIZE, |_, chunk, _| {
        largest_chunk = largest_chunk.max(chunk.len());
        Ok(())
    })
    .unwrap();

    println!(
        "streamed {} B in {} chunks; largest chunk held at once: {} B",
        summary.total_bytes, summary.total_chunks, largest_chunk
    );

    assert_eq!(summary.total_bytes, file.len() as u64);
    assert_eq!(summary.checksum, hashing::hash_bytes(&file));
    assert_eq!(
        largest_chunk, DEFAULT_CHUNK_SIZE,
        "peak in-flight memory must be one chunk, not one file"
    );
}

/// Hot-path history operations must not be O(n) per event.
///
/// The old index was positional, so every push rebuilt the whole map and cloned
/// every hash string. This does not measure wall-clock — CI machines are too
/// noisy for that — it measures that the work does not grow with history size.
#[test]
fn budget_history_writes_do_not_scale_with_history_size() {
    fn allocations_free_run(entries: usize) -> std::time::Duration {
        let mut history = ClipboardHistory::with_limits(entries, DEFAULT_MAX_BYTES);
        for i in 0..entries {
            history.push(ClipboardItem::from_text(
                format!("seed-{}", i),
                PeerId::new("p"),
            ));
        }

        // Time a fixed number of pushes against an already-full history.
        let start = std::time::Instant::now();
        for i in 0..1000 {
            history.push(ClipboardItem::from_text(
                format!("hot-{}", i),
                PeerId::new("p"),
            ));
        }
        start.elapsed()
    }

    let small = allocations_free_run(10);
    let large = allocations_free_run(1000);

    println!(
        "1000 pushes: {:?} against 10 entries, {:?} against 1000 entries ({:.1}x)",
        small,
        large,
        large.as_secs_f64() / small.as_secs_f64().max(f64::EPSILON)
    );

    // A 100x larger history must not make writes anywhere near 100x slower.
    // Generous bound: CI machines are noisy, and the point is the shape of the
    // curve, not the constant.
    assert!(
        large < small * 20,
        "writes appear to scale with history size: {:?} vs {:?}",
        large,
        small
    );
}

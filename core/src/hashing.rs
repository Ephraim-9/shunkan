//! BLAKE3 chunk hasher for file integrity verification.
//!
//! All file chunk integrity in Shunkan uses BLAKE3 exclusively (INV-05).
//! SHA-256 is **prohibited** — BLAKE3 achieves 15–20 GB/s throughput via SIMD
//! parallelism, orders of magnitude faster than SHA-256 at Wi-Fi 6 speeds.

use crate::DEFAULT_CHUNK_SIZE;

/// Compute the BLAKE3 hash of arbitrary bytes, returning a hex string.
pub fn hash_bytes(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hash.to_hex().to_string()
}

/// Compute the BLAKE3 hash of a byte slice, returning the raw 32-byte hash.
pub fn hash_bytes_raw(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// An incremental hasher for streaming data (e.g., file transfer chunks).
///
/// Wraps [`blake3::Hasher`] to provide a convenient API for hashing data
/// that arrives in chunks over the network.
pub struct StreamHasher {
    hasher: blake3::Hasher,
    bytes_processed: u64,
}

impl StreamHasher {
    /// Create a new StreamHasher.
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
            bytes_processed: 0,
        }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.bytes_processed += data.len() as u64;
    }

    /// Finalize and return the hex-encoded BLAKE3 hash.
    pub fn finalize_hex(&self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }

    /// Finalize and return the raw 32-byte BLAKE3 hash.
    pub fn finalize_raw(&self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }

    /// Return the number of bytes processed so far.
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }
}

impl Default for StreamHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Iterate over a buffer's chunks, yielding borrowed slices and their hashes.
///
/// Borrowed, not copied. The previous version called `chunk.to_vec()` on every
/// chunk, so the returned vector was a second full copy of an input that was
/// already fully in memory — a 2 GB transfer needed 4 GB.
///
/// Uses [`DEFAULT_CHUNK_SIZE`] (64 KiB) as the chunk size.
pub fn chunks_with_hashes(data: &[u8]) -> impl Iterator<Item = (&[u8], String)> + '_ {
    chunks_with_hashes_sized(data, DEFAULT_CHUNK_SIZE)
}

/// Iterate over a buffer's chunks at a specific chunk size.
///
/// # Panics
///
/// Panics if `chunk_size` is zero, matching `slice::chunks`.
pub fn chunks_with_hashes_sized(
    data: &[u8],
    chunk_size: usize,
) -> impl Iterator<Item = (&[u8], String)> + '_ {
    data.chunks(chunk_size)
        .map(|chunk| (chunk, hash_bytes(chunk)))
}

/// Split data into chunks and return owned (chunk_data, chunk_hash) pairs.
///
/// Prefer [`chunks_with_hashes`] unless you genuinely need ownership: this
/// allocates a second full copy of `data`.
pub fn chunk_and_hash(data: &[u8]) -> Vec<(Vec<u8>, String)> {
    chunk_and_hash_with_size(data, DEFAULT_CHUNK_SIZE)
}

/// Split data into chunks of a specific size and return owned pairs.
///
/// Prefer [`chunks_with_hashes_sized`] unless you genuinely need ownership.
pub fn chunk_and_hash_with_size(data: &[u8], chunk_size: usize) -> Vec<(Vec<u8>, String)> {
    chunks_with_hashes_sized(data, chunk_size)
        .map(|(chunk, hash)| (chunk.to_vec(), hash))
        .collect()
}

/// Stream a file from disk chunk by chunk, hashing as it goes.
///
/// Peak memory is one chunk, not one file. The reader is passed each chunk as a
/// borrowed slice together with its index and BLAKE3 hash; returning `Err` stops
/// the walk. Returns the total number of bytes read and the whole-file checksum.
///
/// This is the path a 2 GB transfer — the PRD's designer persona — needs.
pub fn stream_chunks<R, F>(
    mut reader: R,
    chunk_size: usize,
    mut on_chunk: F,
) -> std::io::Result<StreamSummary>
where
    R: std::io::Read,
    F: FnMut(u32, &[u8], &str) -> std::io::Result<()>,
{
    assert!(chunk_size > 0, "chunk_size must be non-zero");

    let mut buf = vec![0u8; chunk_size];
    let mut whole_file = StreamHasher::new();
    let mut index: u32 = 0;
    let mut total_bytes: u64 = 0;

    loop {
        // `read` is allowed to return short reads; fill the chunk before hashing
        // it, or the chunk boundaries would depend on the reader's mood.
        let mut filled = 0;
        while filled < chunk_size {
            match reader.read(&mut buf[filled..])? {
                0 => break,
                n => filled += n,
            }
        }

        if filled == 0 {
            break;
        }

        let chunk = &buf[..filled];
        let hash = hash_bytes(chunk);
        whole_file.update(chunk);
        total_bytes += filled as u64;

        on_chunk(index, chunk, &hash)?;
        index += 1;

        if filled < chunk_size {
            break;
        }
    }

    Ok(StreamSummary {
        total_bytes,
        total_chunks: index,
        checksum: whole_file.finalize_hex(),
    })
}

/// What [`stream_chunks`] observed over a whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSummary {
    /// Total bytes read.
    pub total_bytes: u64,
    /// Number of chunks produced.
    pub total_chunks: u32,
    /// BLAKE3 checksum of the entire file.
    pub checksum: String,
}

/// Verify that a chunk's data matches its expected BLAKE3 hash.
pub fn verify_chunk(data: &[u8], expected_hash: &str) -> bool {
    hash_bytes(data) == expected_hash
}

/// Compute a whole-file checksum from a list of chunk hashes.
///
/// This was called `compute_merkle_root`, which promised a structure it did not
/// build. It is a fold, not a tree: you cannot verify one chunk against the
/// result without every other hash, and there is no partial-verification or
/// repair path. The name now says what it does.
///
/// Two changes beyond the rename: a domain separator, so this checksum cannot
/// collide with any other BLAKE3 use in the protocol, and hashing the raw
/// 32-byte digests rather than their hex encoding.
pub fn compute_file_checksum(chunk_hashes: &[String]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FILE_CHECKSUM_DOMAIN);
    hasher.update(&(chunk_hashes.len() as u64).to_le_bytes());

    for hex in chunk_hashes {
        match decode_hash_hex(hex) {
            // Hash the digest itself, not its textual encoding.
            Some(raw) => hasher.update(&raw),
            // A non-hex entry is not a BLAKE3 digest; fold in its bytes rather
            // than silently dropping it, so it still affects the result.
            None => hasher.update(hex.as_bytes()),
        };
    }

    hasher.finalize().to_hex().to_string()
}

/// Domain separator for [`compute_file_checksum`].
const FILE_CHECKSUM_DOMAIN: &[u8] = b"shunkan-file-checksum-v1";

/// Decode a 64-character hex BLAKE3 digest into its 32 raw bytes.
fn decode_hash_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes_deterministic() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_bytes_different_input() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_bytes_hex_length() {
        let h = hash_bytes(b"test");
        // BLAKE3 produces 32 bytes = 64 hex chars
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn test_hash_bytes_raw() {
        let raw = hash_bytes_raw(b"test");
        assert_eq!(raw.len(), 32);
        // Verify consistency with hex version
        let hex = hash_bytes(b"test");
        assert_eq!(hex::encode(raw), hex);
    }

    #[test]
    fn test_stream_hasher_matches_oneshot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let oneshot = hash_bytes(data);

        let mut stream = StreamHasher::new();
        stream.update(&data[..10]);
        stream.update(&data[10..20]);
        stream.update(&data[20..]);
        let streamed = stream.finalize_hex();

        assert_eq!(oneshot, streamed);
        assert_eq!(stream.bytes_processed(), data.len() as u64);
    }

    #[test]
    fn test_stream_hasher_empty() {
        let hasher = StreamHasher::new();
        let empty_hash = hash_bytes(b"");
        assert_eq!(hasher.finalize_hex(), empty_hash);
        assert_eq!(hasher.bytes_processed(), 0);
    }

    #[test]
    fn test_chunk_and_hash() {
        let data = vec![0u8; 200];
        let chunks = chunk_and_hash_with_size(&data, 64);
        // 200 / 64 = 3 full + 1 partial = 4 chunks
        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[0].0.len(), 64);
        assert_eq!(chunks[1].0.len(), 64);
        assert_eq!(chunks[2].0.len(), 64);
        assert_eq!(chunks[3].0.len(), 8); // 200 - 3*64 = 8
    }

    #[test]
    fn test_chunk_and_hash_default_size() {
        let data = vec![42u8; DEFAULT_CHUNK_SIZE + 1];
        let chunks = chunk_and_hash(&data);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].0.len(), DEFAULT_CHUNK_SIZE);
        assert_eq!(chunks[1].0.len(), 1);
    }

    #[test]
    fn test_verify_chunk_valid() {
        let data = b"chunk data here";
        let hash = hash_bytes(data);
        assert!(verify_chunk(data, &hash));
    }

    #[test]
    fn test_verify_chunk_invalid() {
        let data = b"chunk data here";
        assert!(!verify_chunk(
            data,
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_file_checksum_deterministic() {
        let hashes = vec![
            hash_bytes(b"chunk1"),
            hash_bytes(b"chunk2"),
            hash_bytes(b"chunk3"),
        ];
        let sum1 = compute_file_checksum(&hashes);
        let sum2 = compute_file_checksum(&hashes);
        assert_eq!(sum1, sum2);
        assert_eq!(sum1.len(), 64);
    }

    #[test]
    fn test_file_checksum_order_matters() {
        let h1 = hash_bytes(b"a");
        let h2 = hash_bytes(b"b");
        let sum_ab = compute_file_checksum(&[h1.clone(), h2.clone()]);
        let sum_ba = compute_file_checksum(&[h2, h1]);
        assert_ne!(sum_ab, sum_ba);
    }

    #[test]
    fn test_file_checksum_length_is_bound_in() {
        // Without the length prefix, [ab] and [a, b] could collide once the
        // digests are concatenated.
        let h = hash_bytes(b"x");
        assert_ne!(
            compute_file_checksum(std::slice::from_ref(&h)),
            compute_file_checksum(&[h.clone(), h])
        );
        assert_eq!(compute_file_checksum(&[]).len(), 64);
    }

    #[test]
    fn test_file_checksum_is_domain_separated() {
        // Folding one chunk hash must not equal plain BLAKE3 of that digest, or
        // this checksum could be confused with any other BLAKE3 use.
        let h = hash_bytes(b"only-chunk");
        let raw = decode_hash_hex(&h).unwrap();
        assert_ne!(compute_file_checksum(&[h]), hash_bytes(&raw));
    }

    #[test]
    fn test_file_checksum_tolerates_non_hex_entries() {
        // A malformed entry must still affect the result rather than vanish.
        let a = compute_file_checksum(&["not-a-digest".to_string()]);
        let b = compute_file_checksum(&["also-not-a-digest".to_string()]);
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn test_decode_hash_hex_round_trips() {
        let raw = hash_bytes_raw(b"round trip");
        let hex = hash_bytes(b"round trip");
        assert_eq!(decode_hash_hex(&hex), Some(raw));

        assert_eq!(decode_hash_hex("too short"), None);
        assert_eq!(decode_hash_hex(&"z".repeat(64)), None);
    }

    // ── Borrowed and streaming chunking (F-22) ───────────────────────────────

    #[test]
    fn test_chunks_with_hashes_borrows_the_input() {
        let data: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let chunks: Vec<(&[u8], String)> = chunks_with_hashes_sized(&data, 64).collect();

        assert_eq!(chunks.len(), 4);
        assert_eq!(chunks[3].0.len(), 8);

        // Each yielded slice points into `data` rather than a copy of it.
        for (chunk, _) in &chunks {
            let offset = chunk.as_ptr() as usize - data.as_ptr() as usize;
            assert!(offset < data.len(), "chunk must borrow from the input");
        }
    }

    #[test]
    fn test_chunks_with_hashes_agrees_with_the_owning_version() {
        let data = vec![9u8; 300];
        let borrowed: Vec<String> = chunks_with_hashes_sized(&data, 64)
            .map(|(_, h)| h)
            .collect();
        let owned: Vec<String> = chunk_and_hash_with_size(&data, 64)
            .into_iter()
            .map(|(_, h)| h)
            .collect();
        assert_eq!(borrowed, owned);
    }

    #[test]
    fn test_chunks_with_hashes_default_size() {
        let data = vec![1u8; DEFAULT_CHUNK_SIZE + 5];
        let chunks: Vec<_> = chunks_with_hashes(&data).collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[1].0.len(), 5);
    }

    #[test]
    fn test_stream_chunks_matches_in_memory_chunking() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

        let mut streamed = Vec::new();
        let summary = stream_chunks(&data[..], 64, |index, chunk, hash| {
            streamed.push((index, chunk.to_vec(), hash.to_string()));
            Ok(())
        })
        .unwrap();

        let expected: Vec<_> = chunk_and_hash_with_size(&data, 64);
        assert_eq!(summary.total_chunks as usize, expected.len());
        assert_eq!(summary.total_bytes, data.len() as u64);
        assert_eq!(summary.checksum, hash_bytes(&data));

        for (i, (chunk, hash)) in expected.iter().enumerate() {
            assert_eq!(streamed[i].0, i as u32);
            assert_eq!(&streamed[i].1, chunk);
            assert_eq!(&streamed[i].2, hash);
        }
    }

    #[test]
    fn test_stream_chunks_handles_short_reads() {
        /// A reader that yields one byte at a time, as a slow pipe would.
        struct Dribble<'a>(&'a [u8]);
        impl std::io::Read for Dribble<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }

        let data = vec![7u8; 150];
        let mut sizes = Vec::new();
        let summary = stream_chunks(Dribble(&data), 64, |_, chunk, _| {
            sizes.push(chunk.len());
            Ok(())
        })
        .unwrap();

        // Chunk boundaries must not depend on how the reader felt.
        assert_eq!(sizes, vec![64, 64, 22]);
        assert_eq!(summary.total_bytes, 150);
        assert_eq!(summary.checksum, hash_bytes(&data));
    }

    #[test]
    fn test_stream_chunks_on_empty_input() {
        let mut called = false;
        let summary = stream_chunks(&[][..], 64, |_, _, _| {
            called = true;
            Ok(())
        })
        .unwrap();

        assert!(!called);
        assert_eq!(summary.total_chunks, 0);
        assert_eq!(summary.total_bytes, 0);
        assert_eq!(summary.checksum, hash_bytes(b""));
    }

    #[test]
    fn test_stream_chunks_propagates_callback_errors() {
        let data = [0u8; 200];
        let result = stream_chunks(&data[..], 64, |index, _, _| {
            if index == 1 {
                Err(std::io::Error::other("stop here"))
            } else {
                Ok(())
            }
        });

        assert!(result.is_err());
    }

    /// hex helper for test_hash_bytes_raw — avoids pulling in a hex crate as a dependency.
    mod hex {
        pub fn encode(bytes: impl AsRef<[u8]>) -> String {
            bytes
                .as_ref()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect()
        }
    }
}

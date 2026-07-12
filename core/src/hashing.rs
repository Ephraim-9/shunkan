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

/// Split data into chunks and return a vector of (chunk_data, chunk_hash) pairs.
///
/// Uses [`DEFAULT_CHUNK_SIZE`] (64 KiB) as the chunk size. Each chunk's
/// integrity hash is computed with BLAKE3.
pub fn chunk_and_hash(data: &[u8]) -> Vec<(Vec<u8>, String)> {
    chunk_and_hash_with_size(data, DEFAULT_CHUNK_SIZE)
}

/// Split data into chunks of a specific size and return (chunk_data, chunk_hash) pairs.
pub fn chunk_and_hash_with_size(data: &[u8], chunk_size: usize) -> Vec<(Vec<u8>, String)> {
    data.chunks(chunk_size)
        .map(|chunk| {
            let hash = hash_bytes(chunk);
            (chunk.to_vec(), hash)
        })
        .collect()
}

/// Verify that a chunk's data matches its expected BLAKE3 hash.
pub fn verify_chunk(data: &[u8], expected_hash: &str) -> bool {
    hash_bytes(data) == expected_hash
}

/// Compute a Merkle-style root hash from a list of chunk hashes.
///
/// This is a simple concatenation-based approach: hash all chunk hashes
/// together to produce a single root hash for the entire file.
pub fn compute_merkle_root(chunk_hashes: &[String]) -> String {
    let mut hasher = blake3::Hasher::new();
    for h in chunk_hashes {
        hasher.update(h.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
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
        assert!(!verify_chunk(data, "0000000000000000000000000000000000000000000000000000000000000000"));
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let hashes = vec![
            hash_bytes(b"chunk1"),
            hash_bytes(b"chunk2"),
            hash_bytes(b"chunk3"),
        ];
        let root1 = compute_merkle_root(&hashes);
        let root2 = compute_merkle_root(&hashes);
        assert_eq!(root1, root2);
        assert_eq!(root1.len(), 64);
    }

    #[test]
    fn test_merkle_root_order_matters() {
        let h1 = hash_bytes(b"a");
        let h2 = hash_bytes(b"b");
        let root_ab = compute_merkle_root(&[h1.clone(), h2.clone()]);
        let root_ba = compute_merkle_root(&[h2, h1]);
        assert_ne!(root_ab, root_ba);
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

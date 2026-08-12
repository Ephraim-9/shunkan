//! File transfer reassembly.
//!
//! [`FileChunk`] has carried `chunk_index` and `total_chunks` since the
//! protocol was written, but nothing consumed them: there was no reassembly
//! path anywhere in the codebase. This module is that path.
//!
//! Each transfer travels on its own QUIC stream (see [`crate::transport`]), so
//! chunks arrive in order in the common case. The reassembler does not rely on
//! that — it places chunks by index, so a resumed or multiplexed transfer
//! reassembles correctly too, and it verifies every chunk's BLAKE3 hash before
//! accepting it (INV-05).

use crate::protocol::FileChunk;
use anyhow::{ensure, Result};

/// Reassembles a file from its chunks, verifying each one on arrival.
#[derive(Debug)]
pub struct FileReassembler {
    transfer_id: String,
    filename: String,
    total_size: u64,
    total_chunks: u32,
    chunks: Vec<Option<Vec<u8>>>,
    received: u32,
    bytes_received: u64,
}

impl FileReassembler {
    /// Start a reassembly from the first chunk of a transfer.
    pub fn new(chunk: &FileChunk) -> Result<Self> {
        ensure!(
            chunk.total_chunks > 0,
            "Transfer {} declares zero chunks",
            chunk.transfer_id
        );
        ensure!(
            chunk.chunk_index < chunk.total_chunks,
            "Chunk index {} out of range for {} chunks",
            chunk.chunk_index,
            chunk.total_chunks
        );

        let mut reassembler = Self {
            transfer_id: chunk.transfer_id.clone(),
            filename: chunk.filename.clone(),
            total_size: chunk.total_size,
            total_chunks: chunk.total_chunks,
            chunks: vec![None; chunk.total_chunks as usize],
            received: 0,
            bytes_received: 0,
        };
        reassembler.accept(chunk)?;
        Ok(reassembler)
    }

    /// Accept a chunk. Returns `true` once every chunk has arrived.
    ///
    /// Rejects chunks belonging to another transfer, out-of-range indexes,
    /// metadata that contradicts the first chunk, and chunks whose data does
    /// not match their declared BLAKE3 hash. A duplicate of an already-stored
    /// chunk is ignored rather than treated as an error — a retransmit is not
    /// a protocol violation.
    pub fn accept(&mut self, chunk: &FileChunk) -> Result<bool> {
        ensure!(
            chunk.transfer_id == self.transfer_id,
            "Chunk belongs to transfer {}, expected {}",
            chunk.transfer_id,
            self.transfer_id
        );
        ensure!(
            chunk.total_chunks == self.total_chunks,
            "Transfer {} changed chunk count from {} to {}",
            self.transfer_id,
            self.total_chunks,
            chunk.total_chunks
        );
        ensure!(
            chunk.total_size == self.total_size,
            "Transfer {} changed total size from {} to {}",
            self.transfer_id,
            self.total_size,
            chunk.total_size
        );
        ensure!(
            chunk.chunk_index < self.total_chunks,
            "Chunk index {} out of range for {} chunks",
            chunk.chunk_index,
            self.total_chunks
        );
        ensure!(
            chunk.verify(),
            "Chunk {} of transfer {} failed BLAKE3 verification",
            chunk.chunk_index,
            self.transfer_id
        );

        let slot = &mut self.chunks[chunk.chunk_index as usize];
        if slot.is_some() {
            log::debug!(
                "Ignoring duplicate chunk {} of transfer {}",
                chunk.chunk_index,
                self.transfer_id
            );
            return Ok(self.is_complete());
        }

        self.bytes_received += chunk.data.len() as u64;
        ensure!(
            self.bytes_received <= self.total_size,
            "Transfer {} exceeded its declared size of {} bytes",
            self.transfer_id,
            self.total_size
        );

        *slot = Some(chunk.data.clone());
        self.received += 1;

        Ok(self.is_complete())
    }

    /// Whether every chunk has arrived.
    pub fn is_complete(&self) -> bool {
        self.received == self.total_chunks
    }

    /// Indexes of chunks not yet received — what a resume request would ask for.
    pub fn missing_chunks(&self) -> Vec<u32> {
        self.chunks
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.is_none())
            .map(|(idx, _)| idx as u32)
            .collect()
    }

    /// Fraction of the transfer received, in `0.0..=1.0`.
    pub fn progress(&self) -> f64 {
        if self.total_chunks == 0 {
            return 1.0;
        }
        f64::from(self.received) / f64::from(self.total_chunks)
    }

    /// The transfer's identifier.
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }

    /// The original filename.
    pub fn filename(&self) -> &str {
        &self.filename
    }

    /// The declared total size in bytes.
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Bytes received so far.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Consume the reassembler and produce the complete file.
    ///
    /// Errors if chunks are still missing or the reassembled length does not
    /// match the declared total size.
    pub fn finish(self) -> Result<Vec<u8>> {
        ensure!(
            self.is_complete(),
            "Transfer {} is incomplete: {} of {} chunks received",
            self.transfer_id,
            self.received,
            self.total_chunks
        );

        let mut out = Vec::with_capacity(self.total_size as usize);
        for (idx, slot) in self.chunks.into_iter().enumerate() {
            let data = slot.ok_or_else(|| anyhow::anyhow!("Chunk {} missing at assembly", idx))?;
            out.extend_from_slice(&data);
        }

        ensure!(
            out.len() as u64 == self.total_size,
            "Transfer {} reassembled to {} bytes, expected {}",
            self.transfer_id,
            out.len(),
            self.total_size
        );

        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::chunk_and_hash_with_size;

    fn chunks_for(data: &[u8], chunk_size: usize) -> Vec<FileChunk> {
        let pieces = chunk_and_hash_with_size(data, chunk_size);
        let total = pieces.len() as u32;
        pieces
            .into_iter()
            .enumerate()
            .map(|(idx, (bytes, _))| {
                FileChunk::new(
                    "tx-1",
                    "payload.bin",
                    data.len() as u64,
                    idx as u32,
                    total,
                    bytes,
                )
            })
            .collect()
    }

    #[test]
    fn test_reassembles_in_order() {
        let data: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();
        let chunks = chunks_for(&data, 64);

        let mut reassembler = FileReassembler::new(&chunks[0]).unwrap();
        let mut complete = reassembler.is_complete();
        for chunk in &chunks[1..] {
            complete = reassembler.accept(chunk).unwrap();
        }

        assert!(complete);
        assert_eq!(reassembler.finish().unwrap(), data);
    }

    #[test]
    fn test_reassembles_out_of_order() {
        let data: Vec<u8> = (0..500u32).map(|i| (i % 251) as u8).collect();
        let mut chunks = chunks_for(&data, 64);
        chunks.reverse();

        let mut reassembler = FileReassembler::new(&chunks[0]).unwrap();
        for chunk in &chunks[1..] {
            reassembler.accept(chunk).unwrap();
        }

        assert_eq!(reassembler.finish().unwrap(), data);
    }

    #[test]
    fn test_single_chunk_transfer_completes_immediately() {
        let chunks = chunks_for(b"small", 64);
        assert_eq!(chunks.len(), 1);

        let reassembler = FileReassembler::new(&chunks[0]).unwrap();
        assert!(reassembler.is_complete());
        assert_eq!(reassembler.finish().unwrap(), b"small");
    }

    #[test]
    fn test_duplicate_chunk_is_ignored() {
        let data = vec![7u8; 200];
        let chunks = chunks_for(&data, 64);

        let mut reassembler = FileReassembler::new(&chunks[0]).unwrap();
        reassembler.accept(&chunks[0]).unwrap();
        assert_eq!(reassembler.bytes_received(), 64);

        for chunk in &chunks[1..] {
            reassembler.accept(chunk).unwrap();
        }
        assert_eq!(reassembler.finish().unwrap(), data);
    }

    #[test]
    fn test_missing_chunks_are_reported() {
        let data = vec![1u8; 200];
        let chunks = chunks_for(&data, 64);

        let mut reassembler = FileReassembler::new(&chunks[0]).unwrap();
        reassembler.accept(&chunks[2]).unwrap();

        assert_eq!(reassembler.missing_chunks(), vec![1, 3]);
        assert!(!reassembler.is_complete());
        assert!(reassembler.finish().is_err());
    }

    #[test]
    fn test_tampered_chunk_is_rejected() {
        let data = vec![3u8; 200];
        let chunks = chunks_for(&data, 64);

        let mut reassembler = FileReassembler::new(&chunks[0]).unwrap();
        let mut tampered = chunks[1].clone();
        tampered.data = vec![0xFF; 64];

        let err = reassembler.accept(&tampered).unwrap_err();
        assert!(err.to_string().contains("BLAKE3 verification"));
        assert_eq!(reassembler.missing_chunks(), vec![1, 2, 3]);
    }

    #[test]
    fn test_chunk_from_another_transfer_is_rejected() {
        let chunks = chunks_for(&[1u8; 200], 64);
        let mut reassembler = FileReassembler::new(&chunks[0]).unwrap();

        let foreign = FileChunk::new("tx-other", "payload.bin", 200, 1, 4, vec![2u8; 64]);
        assert!(reassembler.accept(&foreign).is_err());
    }

    #[test]
    fn test_shifting_metadata_is_rejected() {
        let chunks = chunks_for(&[1u8; 200], 64);
        let mut reassembler = FileReassembler::new(&chunks[0]).unwrap();

        let wrong_count = FileChunk::new("tx-1", "payload.bin", 200, 1, 9, vec![2u8; 64]);
        assert!(reassembler.accept(&wrong_count).is_err());

        let wrong_size = FileChunk::new("tx-1", "payload.bin", 999, 1, 4, vec![2u8; 64]);
        assert!(reassembler.accept(&wrong_size).is_err());
    }

    #[test]
    fn test_out_of_range_index_is_rejected() {
        let chunks = chunks_for(&[1u8; 200], 64);
        let mut reassembler = FileReassembler::new(&chunks[0]).unwrap();

        let beyond = FileChunk::new("tx-1", "payload.bin", 200, 99, 4, vec![2u8; 64]);
        assert!(reassembler.accept(&beyond).is_err());
    }

    #[test]
    fn test_first_chunk_larger_than_declared_size_is_rejected() {
        // A sender that declares 10 bytes and immediately ships 64 is caught at
        // construction, so no buffer is ever sized from the lie.
        let first = FileChunk::new("tx-1", "lie.bin", 10, 0, 2, vec![0u8; 64]);
        let err = FileReassembler::new(&first).unwrap_err();
        assert!(err.to_string().contains("exceeded its declared size"));
    }

    #[test]
    fn test_transfer_growing_past_declared_size_is_rejected() {
        // Chunks whose combined length exceeds the declared total size must not
        // be allowed to grow the output buffer without bound.
        let first = FileChunk::new("tx-1", "lie.bin", 70, 0, 2, vec![0u8; 64]);
        let second = FileChunk::new("tx-1", "lie.bin", 70, 1, 2, vec![0u8; 64]);

        let mut reassembler = FileReassembler::new(&first).unwrap();
        let err = reassembler.accept(&second).unwrap_err();
        assert!(err.to_string().contains("exceeded its declared size"));
        assert!(!reassembler.is_complete());
    }

    #[test]
    fn test_zero_chunk_transfer_is_rejected() {
        let bogus = FileChunk::new("tx-1", "empty.bin", 0, 0, 0, vec![]);
        assert!(FileReassembler::new(&bogus).is_err());
    }

    #[test]
    fn test_progress_advances_monotonically() {
        let chunks = chunks_for(&vec![5u8; 256], 64);
        let mut reassembler = FileReassembler::new(&chunks[0]).unwrap();
        assert!((reassembler.progress() - 0.25).abs() < f64::EPSILON);

        reassembler.accept(&chunks[1]).unwrap();
        assert!((reassembler.progress() - 0.5).abs() < f64::EPSILON);

        reassembler.accept(&chunks[2]).unwrap();
        reassembler.accept(&chunks[3]).unwrap();
        assert!((reassembler.progress() - 1.0).abs() < f64::EPSILON);
        assert_eq!(reassembler.filename(), "payload.bin");
        assert_eq!(reassembler.total_size(), 256);
        assert_eq!(reassembler.transfer_id(), "tx-1");
    }
}

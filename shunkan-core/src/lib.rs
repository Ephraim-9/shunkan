//! shunkan-core – core library for Project Shunkan
//!
//! This crate provides the fundamental building blocks:
//!   * mDNS service discovery (`Discovery`)
//!   * QUIC transport (`Transport`)
//!   * BLAKE3 chunk hashing (`ChunkHasher`)
//!   * Clipboard sync primitives (`ClipboardEvent`)
//!
//! The API is deliberately minimal and async‑first so that the desktop and
//! Android modules can embed it without pulling in heavy UI dependencies.
//!
//! All public items are re‑exported from the sub‑modules for a clean ergonomics.
//!
//! # Modules
//!
//! * `discovery` – zero‑configuration network discovery using the `mdns` crate.
//! * `transport` – QUIC transport layer built on `quinn`.
//! * `hashing` – chunked file hashing with `blake3`.
//! * `clipboard` – serialisable clipboard events (text, rich‑text, bitmap).
//!
//! The crate follows the architectural invariants documented in `memory.html`.
//!
//! ## Usage example (pseudo‑code)
//! ```rust
//! use shunkan_core::{Discovery, Transport, ClipboardEvent};
//! 
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let disc = Discovery::new()?;
//!     let transport = Transport::bind(4433).await?;
//!     // ... attach event listeners, etc.
//!     Ok(())
//! }
//! ```
//! ```
//!
//! The actual implementation details are in the sub‑modules.
//!
//! # Errors
//! All functions return `anyhow::Result` to simplify error handling across
//! modules.
//!
//! # Logging
//! Use the `log` crate; the host (desktop or Android) is responsible for
//! initialising a logger implementation.

pub mod discovery;
pub mod transport;
pub mod hashing;
pub mod clipboard;

pub use discovery::Discovery;
pub use transport::Transport;
pub use hashing::ChunkHasher;
pub use clipboard::ClipboardEvent;

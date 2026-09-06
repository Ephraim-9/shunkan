//! Shunkan Desktop Linux — daemon entry point.
//!
//! Everything of substance lives in the library crate; this binary only sets up
//! logging and hands off to [`shunkan_desktop::run`]. Keeping it this thin is
//! what lets the Tauri wrapper reuse the same daemon without duplicating it.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    shunkan_desktop::init_logging();
    shunkan_desktop::run().await
}

//! Shunkan Desktop Linux — entry point.
//!
//! Runs the Tauri application by default; `--headless` runs the same engine
//! without a window, which is what CI and remote machines want.

// Tauri apps should not open a console window on Windows in release builds.
// Harmless on Linux, and keeps the attribute where a reader expects it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::Result;

fn main() -> Result<()> {
    shunkan_desktop::init_logging();

    if std::env::args().any(|arg| arg == "--headless") {
        return tauri::async_runtime::block_on(shunkan_desktop::run());
    }

    shunkan_desktop::run_app()
}

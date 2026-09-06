//! Tauri build script.
//!
//! Generates the context (config, assets, capabilities) that
//! `tauri::generate_context!()` expands at compile time. Without this the crate
//! was named `src-tauri` while containing no Tauri at all.

fn main() {
    tauri_build::build()
}

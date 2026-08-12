//! UniFFI binding generator for shunkan-core.
//!
//! The bindgen must be built against the *same* uniffi version as the library,
//! so it ships as a binary in this crate rather than being installed globally:
//!
//! ```text
//! cargo run --bin uniffi-bindgen -- generate \
//!     --library target/aarch64-linux-android/release/libshunkan_core.so \
//!     --language kotlin --out-dir ../mobile-android/app/src/main/java
//! ```
//!
//! `scripts/build-android.sh` wraps this together with the cargo-ndk step.

fn main() {
    uniffi::uniffi_bindgen_main()
}

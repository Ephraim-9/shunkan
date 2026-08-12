#!/usr/bin/env bash
#
# Build libshunkan_core.so for Android and generate its Kotlin bindings.
#
# This is the step that was missing entirely: `core/Cargo.toml` declared no
# crate-type, so the .so the Gradle config pointed at could never have been
# produced, and there was no bindgen step to generate the Kotlin either.
#
# Usage:
#   scripts/build-android.sh [debug|release]
#
# Requires:
#   - cargo-ndk            cargo install cargo-ndk
#   - Android NDK          $ANDROID_NDK_HOME or $ANDROID_NDK_ROOT
#   - Rust Android targets rustup target add aarch64-linux-android x86_64-linux-android

set -euo pipefail

PROFILE="${1:-debug}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_APP="$REPO_ROOT/mobile-android/app"
JNI_LIBS="$ANDROID_APP/src/main/jniLibs"
KOTLIN_OUT="$ANDROID_APP/src/main/java"

# ABIs must match `ndk { abiFilters }` in app/build.gradle.kts.
ABIS=(arm64-v8a x86_64)

case "$PROFILE" in
    debug)   CARGO_PROFILE_FLAG="" ; TARGET_SUBDIR="debug" ;;
    release) CARGO_PROFILE_FLAG="--release" ; TARGET_SUBDIR="release" ;;
    *) echo "Usage: $0 [debug|release]" >&2; exit 2 ;;
esac

if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "error: cargo-ndk not found. Install it with: cargo install cargo-ndk" >&2
    exit 1
fi

if [[ -z "${ANDROID_NDK_HOME:-}${ANDROID_NDK_ROOT:-}" ]]; then
    echo "error: set ANDROID_NDK_HOME (or ANDROID_NDK_ROOT) to your NDK install" >&2
    exit 1
fi

echo "==> Building shunkan-core ($PROFILE) for: ${ABIS[*]}"
mkdir -p "$JNI_LIBS"

ndk_args=()
for abi in "${ABIS[@]}"; do
    ndk_args+=(-t "$abi")
done

cd "$REPO_ROOT"
cargo ndk "${ndk_args[@]}" -o "$JNI_LIBS" build -p shunkan-core $CARGO_PROFILE_FLAG

echo "==> Native libraries:"
find "$JNI_LIBS" -name 'libshunkan_core.so' -printf '    %p (%s bytes)\n'

# Generate the Kotlin bindings from a built library. Any ABI will do — the
# metadata is identical — but it must be a real artifact, so the bindings can
# never drift from the code that ships.
LIB_FOR_BINDGEN="$(find "$JNI_LIBS" -name 'libshunkan_core.so' | head -n 1)"
if [[ -z "$LIB_FOR_BINDGEN" ]]; then
    echo "error: no libshunkan_core.so was produced" >&2
    exit 1
fi

echo "==> Generating Kotlin bindings from $LIB_FOR_BINDGEN"
mkdir -p "$KOTLIN_OUT"
cargo run -q -p shunkan-core --bin uniffi-bindgen -- \
    generate \
    --library "$LIB_FOR_BINDGEN" \
    --language kotlin \
    --out-dir "$KOTLIN_OUT"

echo "==> Bindings:"
find "$KOTLIN_OUT/uniffi" -name '*.kt' -printf '    %p\n' 2>/dev/null || true

echo
echo "Done. Now build the APK:"
echo "    cd mobile-android && ./gradlew assembleDebug"
echo
echo "(Built with the $TARGET_SUBDIR profile.)"

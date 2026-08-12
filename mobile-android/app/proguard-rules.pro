# Shunkan ProGuard/R8 rules.
#
# build.gradle.kts referenced this file while it did not exist, so a release
# build would have failed on a missing file before it ever reached a rule.

# UniFFI's generated bindings are reached over JNA, which resolves method and
# structure names reflectively. Stripping or renaming them breaks the FFI at
# runtime rather than at build time, which is the worst way to find out.
-keep class uniffi.shunkan_core.** { *; }
-keep class com.sun.jna.** { *; }
-keepclassmembers class * extends com.sun.jna.** { *; }
-keep interface com.sun.jna.** { *; }

# Callback interfaces are implemented in Kotlin and invoked from Rust.
-keep class com.shunkan.sync.EngineHolder$* { *; }

# Manifest-declared components are instantiated by name.
-keep class com.shunkan.sync.ime.ShunkanIME { *; }
-keep class com.shunkan.sync.tile.ShunkanTileService { *; }
-keep class com.shunkan.sync.share.ShareTargetActivity { *; }
-keep class com.shunkan.sync.SyncService { *; }
-keep class com.shunkan.sync.ShunkanApplication { *; }

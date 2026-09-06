# ADR-006: Android clipboard capture is user-initiated

**Status:** accepted
**Supersedes:** the implicit assumption that the Linux poll-based model ports to Android

## Context

`app/build.gradle.kts` carried `minSdk = 29` with the comment *"Android 10+
required for clipboard restrictions"*. That has it backwards. Android 10 (API
29) is precisely the release where background clipboard reads were **removed**:

> Unless your app is the default input method editor (IME) or is the app that
> currently has focus, your app cannot access clipboard data on Android 10 or
> higher.
> — [Android 10 privacy changes](https://developer.android.com/about/versions/10/privacy/changes#clipboard-data)

So there is no version of "poll `ClipboardManager` in the background" that works
on our minimum supported release, let alone on newer ones. And the project's own
invariants close the usual escape hatches:

- **INV-03** prohibits polling loops on Android threads.
- **INV-03** also prohibits `AccessibilityService`, which is the workaround apps
  reach for and the one Google Play increasingly rejects.

The audit found no design in the codebase for this — just a desktop model that
could not be ported and no alternative anywhere.

## Decision

Android clipboard capture is **user-initiated by design**, delivered through
three platform-sanctioned components. All three are declared in
`AndroidManifest.xml` and stubbed in `app/src/main/java/com/shunkan/sync/`.

### 1. `ShunkanIME` — an `InputMethodService` (capture)

The IME is the one component Android permits to observe the clipboard while not
the focused app. When Shunkan is the active keyboard it registers an
`OnPrimaryClipChangedListener` — **event-driven, not polled**, satisfying INV-03
— and hands each change to the engine.

This is opt-in, appears in system settings, and the user knowingly enabled it.
That is a *better* privacy story than an accessibility-service workaround, not a
concession.

Status: the capture path is wired; the keyboard input view is not implemented.
An IME with no input view can be enabled but should not be anyone's only
keyboard.

### 2. `ShareTargetActivity` — an `ACTION_SEND` target (explicit send)

The **primary** Android → desktop route. The user picks "Send with Shunkan" from
any share sheet and the text goes to their paired devices.

This is the part that changes the product, so it is worth stating plainly:
**Android → desktop clipboard sync is not automatic.** The user acts. Desktop →
Android remains automatic, because receiving has no such restriction.

### 3. `ShunkanTileService` — a quick-settings tile (control)

Toggles sync from the notification shade. When the honest answer to "is
something reading my clipboard right now" needs to be checkable in one swipe,
the toggle belongs one swipe away.

## Consequences

- **The PRD must say so.** Any claim of automatic bidirectional clipboard sync
  is wrong for the Android → desktop direction. It is user-initiated, by
  platform design, and presenting it as a deliberate privacy property is both
  accurate and the better story.
- A foreground service (`SyncService`) holds the engine and the socket while
  sync is on, with a persistent notification. That is what the platform
  requires, and it is honest about what is running.
- The IME needs a real keyboard before it is shippable as a default.
- No `AccessibilityService`, ever. INV-03 prohibits it and the platform is
  moving against it.

## Alternatives rejected

| Alternative | Why not |
|---|---|
| Poll `ClipboardManager` from a foreground service | Returns null on API 29+ unless focused. Also violates INV-03. |
| `AccessibilityService` to observe the clipboard | Prohibited by INV-03; abuse of an accessibility API; a Play Store risk. |
| Read the clipboard on app resume only | Works, but syncs only what the user copied *before* opening the app — surprising and lossy. Kept as a possible supplement, not the mechanism. |
| Target `minSdk` below 29 to keep background reads | Abandons the security model the whole product is premised on, for two releases of reach. |

## References

- Audit finding F-35, `audit.html`
- INV-03, `memory.html`
- `app/src/main/java/com/shunkan/sync/ime/ShunkanIME.kt`
- `app/src/main/java/com/shunkan/sync/share/ShareTargetActivity.kt`
- `app/src/main/java/com/shunkan/sync/tile/ShunkanTileService.kt`

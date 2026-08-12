package com.shunkan.sync.ime

import android.content.ClipboardManager
import android.content.Context
import android.inputmethodservice.InputMethodService
import android.util.Log
import android.view.View
import com.shunkan.sync.EngineHolder

/**
 * The clipboard **capture** surface on Android.
 *
 * ## Why this exists at all
 *
 * `minSdk = 29` was commented "Android 10+ required for clipboard restrictions",
 * which had it backwards: Android 10 is precisely where background clipboard
 * reads were *removed*. Only the default IME or the currently focused app may
 * call `ClipboardManager.getPrimaryClip()`. INV-03 rules out polling and
 * prohibits AccessibilityService, so the desktop's poll-based model cannot be
 * ported — there is nothing to port it to.
 *
 * An `InputMethodService` is the one component the platform sanctions for this.
 * It is opt-in, it appears in system settings, and the user knows they enabled
 * it. That is a better privacy story than an accessibility-service workaround,
 * not a worse one.
 *
 * ## What it does
 *
 * While Shunkan is the active IME, clipboard changes are read here and handed
 * to the engine. When it is not, Android → desktop sync is user-initiated via
 * [com.shunkan.sync.share.ShareTargetActivity] — by design, and the PRD says so.
 *
 * ## Status
 *
 * The capture path is wired; the keyboard itself is not implemented. A real IME
 * needs a full input view before it can be anyone's default keyboard, and that
 * is feature work this phase deliberately does not start.
 */
class ShunkanIME : InputMethodService() {

    private var clipboardManager: ClipboardManager? = null

    private val clipListener = ClipboardManager.OnPrimaryClipChangedListener {
        onClipboardChanged()
    }

    override fun onCreate() {
        super.onCreate()
        EngineHolder.init(applicationContext)
        clipboardManager = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        // Event-driven, not polled: the platform tells us (INV-03).
        clipboardManager?.addPrimaryClipChangedListener(clipListener)
        Log.i(TAG, "Shunkan IME created; clipboard capture active")
    }

    override fun onDestroy() {
        clipboardManager?.removePrimaryClipChangedListener(clipListener)
        clipboardManager = null
        super.onDestroy()
    }

    override fun onCreateInputView(): View? {
        // TODO: the actual keyboard. Until this exists, the IME can be enabled
        // for capture but should not be anyone's only keyboard.
        return null
    }

    private fun onClipboardChanged() {
        val clip = clipboardManager?.primaryClip ?: return
        if (clip.itemCount == 0) return

        val text = clip.getItemAt(0).coerceToText(this)?.toString().orEmpty()
        if (text.isEmpty()) return

        val engine = EngineHolder.engine ?: return
        if (!engine.isRunning()) return

        try {
            val delivered = engine.sendClipboard(text)
            Log.d(TAG, "Clipboard change sent to $delivered peer(s)")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to send clipboard content", e)
        }
    }

    private companion object {
        const val TAG = "ShunkanIME"
    }
}

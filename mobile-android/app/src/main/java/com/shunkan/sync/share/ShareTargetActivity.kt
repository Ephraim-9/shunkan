package com.shunkan.sync.share

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import com.shunkan.sync.EngineHolder
import com.shunkan.sync.R

/**
 * The explicit "send this to my other devices" path.
 *
 * This is the **primary** Android → desktop route, not a fallback. Since
 * Android 10 removed background clipboard access, a share target is how a user
 * says "send this", and saying so explicitly is a feature: nothing leaves the
 * phone without an intentional act.
 *
 * Finishes immediately; it never shows UI beyond a toast.
 */
class ShareTargetActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        EngineHolder.init(applicationContext)

        val text = extractText(intent)
        if (text.isNullOrEmpty()) {
            toast(getString(R.string.share_nothing_to_send))
            finish()
            return
        }

        val engine = EngineHolder.engine
        if (engine == null || !engine.isRunning()) {
            toast(getString(R.string.share_sync_off))
            finish()
            return
        }

        try {
            val delivered = engine.sendClipboard(text)
            toast(
                if (delivered > 0u) {
                    resources.getQuantityString(R.plurals.share_sent, delivered.toInt(), delivered.toInt())
                } else {
                    getString(R.string.share_no_peers)
                },
            )
        } catch (e: Exception) {
            Log.w(TAG, "Share failed", e)
            toast(getString(R.string.share_failed))
        }
        finish()
    }

    private fun extractText(intent: Intent?): String? {
        if (intent?.action != Intent.ACTION_SEND) return null
        return intent.getStringExtra(Intent.EXTRA_TEXT)
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }

    private companion object {
        const val TAG = "ShunkanShare"
    }
}

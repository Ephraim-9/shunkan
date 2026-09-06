package com.shunkan.sync

import android.content.Context
import android.util.Log
import uniffi.shunkan_core.FfiPeer
import uniffi.shunkan_core.ShunkanEngine
import uniffi.shunkan_core.ShunkanListener
import java.util.concurrent.atomic.AtomicReference

/**
 * Process-wide holder for the Rust engine.
 *
 * The engine is created once and shared by every component. `data_dir` is the
 * app's private `filesDir`, which is where the device identity, its private key
 * and the paired-device store live — the same layout the Linux daemon uses
 * under `$XDG_DATA_HOME/shunkan`.
 */
object EngineHolder {
    private const val TAG = "Shunkan"

    private val engineRef = AtomicReference<ShunkanEngine?>(null)
    private val listeners = mutableListOf<EngineEvents>()

    /** Events the UI layers can observe without each holding a Rust callback. */
    interface EngineEvents {
        fun onClipboardReceived(text: String, sourcePeer: String) {}
        fun onPeersChanged() {}
        fun onPairingResult(peerId: String, accepted: Boolean, reason: String?) {}
        fun onError(message: String) {}
    }

    /** The engine, or null if it could not be created. */
    val engine: ShunkanEngine? get() = engineRef.get()

    /** Create the engine if it does not exist yet. Safe to call repeatedly. */
    @Synchronized
    fun init(context: Context) {
        if (engineRef.get() != null) return
        try {
            val engine = ShunkanEngine(
                dataDir = context.filesDir.absolutePath,
                deviceName = android.os.Build.MODEL ?: "Android",
            )
            engineRef.set(engine)
            Log.i(TAG, "Engine ready: ${engine.peerId()}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create the Shunkan engine", e)
        }
    }

    /** Start discovery and the listener. Idempotent. */
    @Synchronized
    fun start() {
        val engine = engineRef.get() ?: return
        if (engine.isRunning()) return
        try {
            engine.start(Fanout)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start the engine", e)
        }
    }

    /** Stop syncing. */
    @Synchronized
    fun stop() {
        engineRef.get()?.stop()
    }

    /** Whether sync is currently running. */
    fun isRunning(): Boolean = engineRef.get()?.isRunning() ?: false

    /** Currently known peers. */
    fun peers(): List<FfiPeer> = engineRef.get()?.peers() ?: emptyList()

    @Synchronized
    fun addListener(listener: EngineEvents) {
        listeners.add(listener)
    }

    @Synchronized
    fun removeListener(listener: EngineEvents) {
        listeners.remove(listener)
    }

    @Synchronized
    private fun snapshot(): List<EngineEvents> = listeners.toList()

    /**
     * The single Rust-side listener, fanned out to Kotlin observers.
     *
     * Callbacks arrive on a Rust thread, so anything touching the UI must post
     * to the main looper itself.
     */
    private object Fanout : ShunkanListener {
        override fun onClipboardReceived(text: String, sourcePeer: String) {
            snapshot().forEach { it.onClipboardReceived(text, sourcePeer) }
        }

        override fun onPeersChanged() {
            snapshot().forEach { it.onPeersChanged() }
        }

        override fun onPairingResult(peerId: String, accepted: Boolean, reason: String?) {
            snapshot().forEach { it.onPairingResult(peerId, accepted, reason) }
        }

        override fun onError(message: String) {
            Log.w(TAG, "Engine error: $message")
            snapshot().forEach { it.onError(message) }
        }
    }
}

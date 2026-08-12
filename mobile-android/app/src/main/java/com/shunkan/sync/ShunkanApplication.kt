package com.shunkan.sync

import android.app.Application

/**
 * Application entry point.
 *
 * Deliberately thin: it owns nothing but the process-wide [EngineHolder], so
 * the IME, the share target and the tile all talk to one engine rather than
 * three.
 */
class ShunkanApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        EngineHolder.init(this)
    }
}

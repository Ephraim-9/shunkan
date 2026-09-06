package com.shunkan.sync

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder

/**
 * Foreground service that keeps the engine alive while sync is on.
 *
 * A foreground service is what Android requires to hold a socket open, and it
 * is also the honest thing to show the user: sync is running, here is the
 * notification saying so.
 *
 * Note that this service does **not** read the clipboard. Nothing in the app
 * does, in the background — see CAPTURE-DESIGN.md.
 */
class SyncService : Service() {

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification())
        EngineHolder.start()
        return START_STICKY
    }

    override fun onDestroy() {
        EngineHolder.stop()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.sync_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        getSystemService(NotificationManager::class.java)?.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.sync_running))
            .setSmallIcon(R.drawable.ic_tile)
            .setOngoing(true)
            .build()

    companion object {
        private const val CHANNEL_ID = "shunkan-sync"
        private const val NOTIFICATION_ID = 1

        /** Start syncing. */
        fun start(context: Context) {
            val intent = Intent(context, SyncService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /** Stop syncing. */
        fun stop(context: Context) {
            context.stopService(Intent(context, SyncService::class.java))
        }
    }
}

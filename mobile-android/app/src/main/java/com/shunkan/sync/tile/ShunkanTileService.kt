package com.shunkan.sync.tile

import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import com.shunkan.sync.EngineHolder
import com.shunkan.sync.R
import com.shunkan.sync.SyncService

/**
 * Quick-settings tile for toggling sync.
 *
 * The third component of the capture design (ADR-006): capture via the IME,
 * explicit sends via the share target, and this for "is it on right now".
 * Having the toggle one swipe away matters when the honest answer to "is
 * something reading my clipboard" needs to be checkable in a second.
 */
class ShunkanTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        refresh()
    }

    override fun onClick() {
        super.onClick()
        if (EngineHolder.isRunning()) {
            SyncService.stop(applicationContext)
        } else {
            SyncService.start(applicationContext)
        }
        refresh()
    }

    private fun refresh() {
        val tile = qsTile ?: return
        val running = EngineHolder.isRunning()
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(if (running) R.string.tile_on else R.string.tile_off)
        tile.updateTile()
    }
}

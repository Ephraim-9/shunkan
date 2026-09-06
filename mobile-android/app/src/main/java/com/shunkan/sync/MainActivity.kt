package com.shunkan.sync

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import uniffi.shunkan_core.FfiPeer

/**
 * The one screen the app has so far: pairing and peer status.
 *
 * Deliberately minimal. The audit's instruction for this phase was to settle
 * the capture design before writing feature code, so this is the shell that
 * proves the FFI works end to end, not the finished product.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        EngineHolder.init(applicationContext)
        setContent { MaterialTheme { ShunkanScreen() } }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ShunkanScreen() {
    var running by remember { mutableStateOf(EngineHolder.isRunning()) }
    var peers by remember { mutableStateOf(EngineHolder.peers()) }
    var pin by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf<String?>(null) }

    val engine = EngineHolder.engine
    val context = LocalContext.current

    DisposableEffect(Unit) {
        val listener = object : EngineHolder.EngineEvents {
            override fun onPeersChanged() {
                peers = EngineHolder.peers()
            }

            override fun onPairingResult(peerId: String, accepted: Boolean, reason: String?) {
                status = if (accepted) "Paired with $peerId" else "Pairing failed: ${reason ?: "unknown"}"
                if (accepted) pin = null
            }

            override fun onError(message: String) {
                status = message
            }
        }
        EngineHolder.addListener(listener)
        onDispose { EngineHolder.removeListener(listener) }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Shunkan 瞬間") }) }) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (engine == null) {
                Text("The sync engine failed to start. Check logcat for details.")
                return@Column
            }

            Text("This device: ${engine.peerId()}", fontFamily = FontFamily.Monospace)

            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(
                    checked = running,
                    onCheckedChange = { enabled ->
                        running = enabled
                        if (enabled) SyncService.start(context) else SyncService.stop(context)
                    },
                )
                Spacer(Modifier.width(12.dp))
                Text(if (running) "Sync on" else "Sync off")
            }

            HorizontalDivider()

            Text("Pairing", style = MaterialTheme.typography.titleMedium)
            pin?.let {
                Text("Enter this PIN on the other device:")
                Text(it, style = MaterialTheme.typography.headlineMedium, fontFamily = FontFamily.Monospace)
            }
            Button(onClick = { pin = engine.beginPairingWithGeneratedPin() }) {
                Text("Show a pairing PIN")
            }

            status?.let { Text(it) }

            HorizontalDivider()

            Text("Peers (${peers.size})", style = MaterialTheme.typography.titleMedium)
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(peers) { peer -> PeerRow(peer) }
            }
        }
    }
}

@Composable
private fun PeerRow(peer: FfiPeer) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            Text(peer.deviceName, style = MaterialTheme.typography.bodyLarge)
            Text(
                buildString {
                    append(peer.platform)
                    append(" · ")
                    append(if (peer.connected) "connected" else "offline")
                    if (peer.paired) append(" · paired")
                },
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

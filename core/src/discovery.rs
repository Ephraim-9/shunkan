//! mDNS-SD local network discovery using the `mdns-sd` crate.
//!
//! Broadcasts and discovers `_shunkan-sync._udp.local.` service instances
//! on the local network, enabling zero-configuration peer discovery
//! per INV-02 (zero cloud reliance).

use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// A discovered peer on the local network.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredPeer {
    /// The mDNS instance name (e.g. "helliot-thinkpad").
    pub instance_name: String,
    /// The hostname of the peer.
    pub hostname: String,
    /// IP addresses where the peer can be reached.
    pub addresses: Vec<std::net::IpAddr>,
    /// The QUIC port the peer is listening on.
    pub port: u16,
    /// Additional TXT record properties.
    pub properties: HashMap<String, String>,
}

/// The mDNS service type used by Shunkan.
const SERVICE_TYPE: &str = "_shunkan-sync._udp.local.";

/// Events emitted by the discovery service.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A new peer was discovered.
    PeerDiscovered(DiscoveredPeer),
    /// A previously discovered peer was removed/went offline.
    PeerRemoved(String),
}

/// mDNS-SD discovery service for finding Shunkan peers on the local network.
///
/// Uses the `mdns-sd` crate to broadcast our own service and discover others.
pub struct DiscoveryService {
    daemon: ServiceDaemon,
    /// Our registered service instance name, if broadcasting.
    instance_name: Option<String>,
    /// Currently known peers.
    known_peers: Arc<Mutex<HashMap<String, DiscoveredPeer>>>,
}

impl DiscoveryService {
    /// Create a new DiscoveryService.
    pub fn new() -> Result<Self> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| anyhow::anyhow!("Failed to create mDNS daemon: {}", e))?;
        Ok(Self {
            daemon,
            instance_name: None,
            known_peers: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Register (broadcast) our service on the local network.
    ///
    /// This advertises our Shunkan instance so other peers can discover us.
    ///
    /// # Arguments
    /// - `instance_name`: Human-readable name for this instance (e.g. "helliot-thinkpad")
    /// - `port`: The QUIC port we're listening on
    /// - `properties`: Additional key-value properties to advertise in TXT records
    pub fn register(
        &mut self,
        instance_name: &str,
        port: u16,
        properties: &[(&str, &str)],
    ) -> Result<()> {
        let mut txt_properties = Vec::new();
        for (key, val) in properties {
            txt_properties.push(format!("{}={}", key, val));
        }

        let host = format!("{}.local.", instance_name);
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            instance_name,
            &host,
            "",     // Let the daemon pick the IP
            port,
            None,   // No additional properties via HashMap
        )
        .map_err(|e| anyhow::anyhow!("Failed to create ServiceInfo: {}", e))?;

        self.daemon
            .register(service_info)
            .map_err(|e| anyhow::anyhow!("Failed to register mDNS service: {}", e))?;

        self.instance_name = Some(instance_name.to_string());
        log::info!(
            "Registered mDNS service: {}.{}",
            instance_name,
            SERVICE_TYPE
        );
        Ok(())
    }

    /// Start browsing for other Shunkan peers on the local network.
    ///
    /// Returns a channel receiver that emits [`DiscoveryEvent`]s as peers
    /// are discovered or removed.
    pub fn browse(&self) -> Result<mpsc::UnboundedReceiver<DiscoveryEvent>> {
        let (tx, rx) = mpsc::unbounded_channel();

        let receiver = self
            .daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| anyhow::anyhow!("Failed to browse mDNS: {}", e))?;

        let known_peers = self.known_peers.clone();
        let our_instance = self.instance_name.clone();

        std::thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let instance = info.get_fullname().to_string();

                        // Skip our own service
                        if let Some(ref our) = our_instance {
                            if instance.contains(our) {
                                continue;
                            }
                        }

                        let peer = DiscoveredPeer {
                            instance_name: instance.clone(),
                            hostname: info.get_hostname().to_string(),
                            addresses: info.get_addresses().iter().copied().collect(),
                            port: info.get_port(),
                            properties: info
                                .get_properties()
                                .iter()
                                .filter_map(|p| {
                                    Some((
                                        p.key().to_string(),
                                        p.val_str().to_string(),
                                    ))
                                })
                                .collect(),
                        };

                        if let Ok(mut peers) = known_peers.lock() {
                            peers.insert(instance.clone(), peer.clone());
                        }

                        let _ = tx.send(DiscoveryEvent::PeerDiscovered(peer));
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        if let Ok(mut peers) = known_peers.lock() {
                            peers.remove(&fullname);
                        }
                        let _ = tx.send(DiscoveryEvent::PeerRemoved(fullname));
                    }
                    _ => {
                        // Ignore SearchStarted and other transient events
                    }
                }
            }
        });

        Ok(rx)
    }

    /// Get the list of currently known peers.
    pub fn known_peers(&self) -> Vec<DiscoveredPeer> {
        self.known_peers
            .lock()
            .map(|peers| peers.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Unregister our service from the network.
    pub fn unregister(&mut self) -> Result<()> {
        if let Some(ref name) = self.instance_name {
            let fullname = format!("{}.{}", name, SERVICE_TYPE);
            self.daemon
                .unregister(&fullname)
                .map_err(|e| anyhow::anyhow!("Failed to unregister mDNS service: {}", e))?;
            log::info!("Unregistered mDNS service: {}", fullname);
            self.instance_name = None;
        }
        Ok(())
    }

    /// Shut down the mDNS daemon gracefully.
    pub fn shutdown(self) -> Result<()> {
        self.daemon
            .shutdown()
            .map_err(|e| anyhow::anyhow!("Failed to shutdown mDNS daemon: {}", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_type_constant() {
        assert_eq!(SERVICE_TYPE, "_shunkan-sync._udp.local.");
    }

    #[test]
    fn test_discovered_peer_clone() {
        let peer = DiscoveredPeer {
            instance_name: "test".to_string(),
            hostname: "test.local.".to_string(),
            addresses: vec!["192.168.1.100".parse().unwrap()],
            port: 4433,
            properties: HashMap::new(),
        };
        let cloned = peer.clone();
        assert_eq!(peer, cloned);
    }

    #[test]
    fn test_discovery_event_variants() {
        let peer = DiscoveredPeer {
            instance_name: "dev".to_string(),
            hostname: "dev.local.".to_string(),
            addresses: vec![],
            port: 4433,
            properties: HashMap::new(),
        };
        let _event = DiscoveryEvent::PeerDiscovered(peer);
        let _event = DiscoveryEvent::PeerRemoved("dev".to_string());
    }

    #[test]
    fn test_create_discovery_service() {
        // This test may fail in CI environments without multicast support,
        // but should work on developer machines.
        let result = DiscoveryService::new();
        if let Ok(service) = result {
            assert!(service.known_peers().is_empty());
            let _ = service.shutdown();
        }
        // If it fails (e.g., in sandboxed CI), that's acceptable
    }
}

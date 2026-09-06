//! mDNS-SD local network discovery using the `mdns-sd` crate.
//!
//! Broadcasts and discovers `_shunkan-sync._udp.local.` service instances
//! on the local network, enabling zero-configuration peer discovery
//! per INV-02 (zero cloud reliance).

use anyhow::Result;
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
    /// The peer's parsed Shunkan advertisement, if it published a valid one.
    pub advertisement: Option<ServiceAdvertisement>,
    /// Raw TXT record properties, including any keys outside the schema.
    pub properties: HashMap<String, String>,
}

impl DiscoveredPeer {
    /// The peer's advertised ID, if it published one.
    pub fn peer_id(&self) -> Option<&str> {
        self.advertisement.as_ref().map(|a| a.peer_id.as_str())
    }

    /// The peer's advertised certificate fingerprint, if it published one.
    pub fn fingerprint(&self) -> Option<&str> {
        self.advertisement
            .as_ref()
            .map(|a| a.fingerprint.as_str())
            .filter(|fp| !fp.is_empty())
    }

    /// The first reachable socket address this peer can be dialled on.
    /// Prefers IPv4 since TransportClient binds to 0.0.0.0:0.
    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        self.addresses
            .iter()
            .find(|ip| ip.is_ipv4())
            .map(|ip| std::net::SocketAddr::new(*ip, self.port))
    }
}

/// Decide whether a resolved service is our own advertisement echoed back.
///
/// Prefers the peer ID from the TXT record, which is exact. Falls back to
/// full service-name equality — not `contains`, which would make a peer named
/// `thinkpad` suppress `helliot-thinkpad`.
fn is_self(
    instance: &str,
    advertisement: &Option<ServiceAdvertisement>,
    our_fullname: &Arc<Mutex<Option<String>>>,
    our_peer_id: &Arc<Mutex<Option<String>>>,
) -> bool {
    if let (Some(ad), Ok(ours)) = (advertisement, our_peer_id.lock()) {
        if let Some(ours) = ours.as_deref() {
            return ad.peer_id == ours;
        }
    }
    match our_fullname.lock() {
        Ok(ours) => ours.as_deref() == Some(instance),
        Err(_) => false,
    }
}

/// The mDNS service type used by Shunkan.
const SERVICE_TYPE: &str = "_shunkan-sync._udp.local.";

/// TXT key: the peer's stable identifier.
pub const TXT_PEER_ID: &str = "id";
/// TXT key: the peer's platform (`linux`, `android`, …).
pub const TXT_PLATFORM: &str = "platform";
/// TXT key: the peer's protocol version.
pub const TXT_VERSION: &str = "ver";
/// TXT key: BLAKE3 fingerprint of the peer's TLS certificate.
///
/// This is what lets a browsing peer decide, before dialling, whether the
/// device it just found is one it has already paired with.
pub const TXT_FINGERPRINT: &str = "fp";

/// The advertisement a peer publishes in its mDNS TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAdvertisement {
    /// The peer's stable identifier.
    pub peer_id: String,
    /// The peer's platform.
    pub platform: String,
    /// The peer's protocol version.
    pub version: String,
    /// BLAKE3 fingerprint of the peer's TLS certificate.
    pub fingerprint: String,
}

impl ServiceAdvertisement {
    /// Build an advertisement for this device.
    pub fn new(
        peer_id: impl Into<String>,
        platform: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            platform: platform.into(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            fingerprint: fingerprint.into(),
        }
    }

    /// Render the advertisement as mDNS TXT properties.
    pub fn to_txt_properties(&self) -> HashMap<String, String> {
        HashMap::from([
            (TXT_PEER_ID.to_string(), self.peer_id.clone()),
            (TXT_PLATFORM.to_string(), self.platform.clone()),
            (TXT_VERSION.to_string(), self.version.clone()),
            (TXT_FINGERPRINT.to_string(), self.fingerprint.clone()),
        ])
    }

    /// Parse an advertisement out of a discovered peer's TXT properties.
    ///
    /// Returns `None` if the mandatory peer ID is missing, which is how a
    /// non-Shunkan or pre-TXT-schema responder is filtered out.
    pub fn from_txt_properties(props: &HashMap<String, String>) -> Option<Self> {
        let peer_id = props.get(TXT_PEER_ID)?.clone();
        if peer_id.is_empty() {
            return None;
        }
        Some(Self {
            peer_id,
            platform: props
                .get(TXT_PLATFORM)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            version: props
                .get(TXT_VERSION)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string()),
            fingerprint: props.get(TXT_FINGERPRINT).cloned().unwrap_or_default(),
        })
    }
}

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
    /// Our own fully-qualified service name, shared with the browse thread.
    ///
    /// Shared rather than copied so that `browse()` before `register()` still
    /// filters our own advertisement out once registration happens. Capturing
    /// the value at `browse()` time meant the filter was `None` forever and the
    /// device discovered itself.
    our_fullname: Arc<Mutex<Option<String>>>,
    /// Our own peer ID, used as the authoritative self-filter once TXT records
    /// are available.
    our_peer_id: Arc<Mutex<Option<String>>>,
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
            our_fullname: Arc::new(Mutex::new(None)),
            our_peer_id: Arc::new(Mutex::new(None)),
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
    /// - `advertisement`: Peer identity published in the TXT record
    ///
    /// The service is registered with `enable_addr_auto()`, which is the
    /// `mdns-sd` API for "track this host's addresses and keep the A/AAAA
    /// records current". Without it the record is published with no addresses
    /// at all — resolvable, but unreachable.
    pub fn register(
        &mut self,
        instance_name: &str,
        port: u16,
        advertisement: &ServiceAdvertisement,
    ) -> Result<()> {
        let host = format!("{}.local.", instance_name);
        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            instance_name,
            &host,
            // Addresses come from enable_addr_auto() below rather than being
            // hardcoded here; an empty &str resolves to an empty address set.
            "",
            port,
            advertisement.to_txt_properties(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to create ServiceInfo: {}", e))?
        .enable_addr_auto();

        self.daemon
            .register(service_info)
            .map_err(|e| anyhow::anyhow!("Failed to register mDNS service: {}", e))?;

        self.instance_name = Some(instance_name.to_string());
        *self.our_fullname.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(format!("{}.{}", instance_name, SERVICE_TYPE));
        *self.our_peer_id.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(advertisement.peer_id.clone());
        log::info!(
            "Registered mDNS service: {}.{} (peer {}, port {})",
            instance_name,
            SERVICE_TYPE,
            advertisement.peer_id,
            port
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
        let our_fullname = self.our_fullname.clone();
        let our_peer_id = self.our_peer_id.clone();

        std::thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let instance = info.get_fullname().to_string();

                        let properties: HashMap<String, String> = info
                            .get_properties()
                            .iter()
                            .map(|p| (p.key().to_string(), p.val_str().to_string()))
                            .collect();
                        let advertisement = ServiceAdvertisement::from_txt_properties(&properties);

                        if is_self(&instance, &advertisement, &our_fullname, &our_peer_id) {
                            log::trace!("Ignoring our own advertisement: {}", instance);
                            continue;
                        }

                        let addresses: Vec<std::net::IpAddr> =
                            info.get_addresses().iter().copied().collect();
                        if addresses.is_empty() {
                            log::warn!(
                                "Peer {} resolved with no IP addresses — cannot be dialled",
                                instance
                            );
                        }

                        let peer = DiscoveredPeer {
                            instance_name: instance.clone(),
                            hostname: info.get_hostname().to_string(),
                            addresses,
                            port: info.get_port(),
                            advertisement,
                            properties,
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
            *self.our_fullname.lock().unwrap_or_else(|e| e.into_inner()) = None;
            *self.our_peer_id.lock().unwrap_or_else(|e| e.into_inner()) = None;
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

    fn sample_peer(instance: &str, addresses: Vec<std::net::IpAddr>) -> DiscoveredPeer {
        let advertisement = ServiceAdvertisement::new("peer-abc", "linux", "fp-abc");
        DiscoveredPeer {
            instance_name: instance.to_string(),
            hostname: format!("{}.local.", instance),
            addresses,
            port: 4433,
            properties: advertisement.to_txt_properties(),
            advertisement: Some(advertisement),
        }
    }

    #[test]
    fn test_discovered_peer_clone() {
        let peer = sample_peer("test", vec!["192.168.1.100".parse().unwrap()]);
        let cloned = peer.clone();
        assert_eq!(peer, cloned);
    }

    #[test]
    fn test_discovery_event_variants() {
        let peer = sample_peer("dev", vec![]);
        let _event = DiscoveryEvent::PeerDiscovered(peer);
        let _event = DiscoveryEvent::PeerRemoved("dev".to_string());
    }

    #[test]
    fn test_discovered_peer_accessors() {
        let peer = sample_peer("dev", vec!["10.0.0.5".parse().unwrap()]);
        assert_eq!(peer.peer_id(), Some("peer-abc"));
        assert_eq!(peer.fingerprint(), Some("fp-abc"));
        assert_eq!(
            peer.socket_addr(),
            Some("10.0.0.5:4433".parse::<std::net::SocketAddr>().unwrap())
        );
    }

    #[test]
    fn test_discovered_peer_without_addresses_has_no_socket_addr() {
        let peer = sample_peer("dev", vec![]);
        assert!(peer.socket_addr().is_none());
    }

    #[test]
    fn test_advertisement_txt_round_trip() {
        let ad = ServiceAdvertisement::new("peer-123", "android", "ff00");
        let props = ad.to_txt_properties();

        assert_eq!(props.get(TXT_PEER_ID).unwrap(), "peer-123");
        assert_eq!(props.get(TXT_PLATFORM).unwrap(), "android");
        assert_eq!(props.get(TXT_FINGERPRINT).unwrap(), "ff00");
        assert_eq!(props.get(TXT_VERSION).unwrap(), env!("CARGO_PKG_VERSION"));

        assert_eq!(ServiceAdvertisement::from_txt_properties(&props), Some(ad));
    }

    #[test]
    fn test_advertisement_without_peer_id_is_rejected() {
        let mut props = HashMap::new();
        props.insert(TXT_PLATFORM.to_string(), "linux".to_string());
        assert!(ServiceAdvertisement::from_txt_properties(&props).is_none());

        props.insert(TXT_PEER_ID.to_string(), String::new());
        assert!(ServiceAdvertisement::from_txt_properties(&props).is_none());
    }

    #[test]
    fn test_advertisement_tolerates_missing_optional_keys() {
        let props = HashMap::from([(TXT_PEER_ID.to_string(), "peer-9".to_string())]);
        let ad = ServiceAdvertisement::from_txt_properties(&props).unwrap();
        assert_eq!(ad.peer_id, "peer-9");
        assert_eq!(ad.platform, "unknown");
        assert_eq!(ad.version, "unknown");
        assert!(ad.fingerprint.is_empty());
    }

    #[test]
    fn test_self_filter_matches_on_peer_id() {
        let ours = Arc::new(Mutex::new(Some("peer-me".to_string())));
        let fullname = Arc::new(Mutex::new(Some("me._shunkan-sync._udp.local.".to_string())));

        let mine = Some(ServiceAdvertisement::new("peer-me", "linux", "fp"));
        let theirs = Some(ServiceAdvertisement::new("peer-you", "linux", "fp"));

        assert!(is_self("anything", &mine, &fullname, &ours));
        assert!(!is_self("anything", &theirs, &fullname, &ours));
    }

    #[test]
    fn test_self_filter_uses_full_name_equality_not_substring() {
        let no_peer_id = Arc::new(Mutex::new(None));
        let fullname = Arc::new(Mutex::new(Some(
            "thinkpad._shunkan-sync._udp.local.".to_string(),
        )));

        assert!(is_self(
            "thinkpad._shunkan-sync._udp.local.",
            &None,
            &fullname,
            &no_peer_id
        ));
        // The old `contains` check suppressed this legitimate peer.
        assert!(!is_self(
            "helliot-thinkpad._shunkan-sync._udp.local.",
            &None,
            &fullname,
            &no_peer_id
        ));
    }

    #[test]
    fn test_self_filter_sees_late_registration() {
        // browse() before register(): the shared slot starts empty and is
        // filled in later, so the filter must observe the update.
        let peer_id = Arc::new(Mutex::new(None));
        let fullname = Arc::new(Mutex::new(None));
        let mine = Some(ServiceAdvertisement::new("peer-me", "linux", "fp"));

        assert!(!is_self("x", &mine, &fullname, &peer_id));

        *peer_id.lock().unwrap() = Some("peer-me".to_string());
        assert!(is_self("x", &mine, &fullname, &peer_id));
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

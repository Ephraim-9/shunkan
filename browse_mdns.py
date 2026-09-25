import time
from zeroconf import Zeroconf, ServiceBrowser, ServiceStateChange

def on_service_state_change(zeroconf, service_type, name, state_change):
    print(f"Service {name} of type {service_type} state changed: {state_change}")
    if state_change == ServiceStateChange.Added:
        info = zeroconf.get_service_info(service_type, name)
        if info:
            print(f"  Info: {info}")
            print(f"  Addresses: {[socket.inet_ntoa(a) for a in info.addresses] if info.addresses else []}")
            print(f"  Port: {info.port}")
            print(f"  Properties: {info.properties}")
        else:
            print("  Info: None")

if __name__ == '__main__':
    import socket
    zeroconf = Zeroconf()
    print("Browsing for _shunkan-sync._udp.local.")
    browser = ServiceBrowser(zeroconf, "_shunkan-sync._udp.local.", handlers=[on_service_state_change])
    
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.close()

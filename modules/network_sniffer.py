import scapy.all as scapy
from scapy.layers import http
import time
import threading
import socket
import collections
from datetime import datetime

# Store captured packets
captured_packets = []
packet_counts = {
    'total': 0,
    'tcp': 0, 
    'udp': 0, 
    'icmp': 0, 
    'dns': 0, 
    'http': 0, 
    'other': 0
}
stats_lock = threading.Lock()
src_ips = collections.Counter()
dst_ips = collections.Counter()
src_ports = collections.Counter()
dst_ports = collections.Counter()
protocols = collections.Counter()

def get_interfaces():
    """Get list of available network interfaces"""
    try:
        return scapy.get_if_list()
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return []

def get_local_ip():
    """Get the local IP address of the machine"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def packet_callback(packet):
    """Process each captured packet"""
    global captured_packets, packet_counts
    
    # Add packet to our list
    captured_packets.append(packet)
    
    with stats_lock:
        packet_counts['total'] += 1
        
        # Identify packet type and update counters
        if packet.haslayer(scapy.TCP):
            packet_counts['tcp'] += 1
            protocols['TCP'] += 1
            if packet.haslayer(scapy.IP):
                src_ips[packet[scapy.IP].src] += 1
                dst_ips[packet[scapy.IP].dst] += 1
                src_ports[f"TCP:{packet[scapy.TCP].sport}"] += 1
                dst_ports[f"TCP:{packet[scapy.TCP].dport}"] += 1
        
        elif packet.haslayer(scapy.UDP):
            packet_counts['udp'] += 1
            protocols['UDP'] += 1
            if packet.haslayer(scapy.IP):
                src_ips[packet[scapy.IP].src] += 1
                dst_ips[packet[scapy.IP].dst] += 1
                src_ports[f"UDP:{packet[scapy.UDP].sport}"] += 1
                dst_ports[f"UDP:{packet[scapy.UDP].dport}"] += 1
        
        elif packet.haslayer(scapy.ICMP):
            packet_counts['icmp'] += 1
            protocols['ICMP'] += 1
        
        # Check for DNS packets
        if packet.haslayer(scapy.DNS):
            packet_counts['dns'] += 1
            protocols['DNS'] += 1
        
        # Check for HTTP packets
        if packet.haslayer(http.HTTPRequest):
            packet_counts['http'] += 1
            protocols['HTTP'] += 1
    
    # Print basic packet info
    print_packet_summary(packet)

def print_packet_summary(packet):
    """Print a summary of the packet"""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    summary = f"[{timestamp}] "
    
    if packet.haslayer(scapy.IP):
        summary += f"{packet[scapy.IP].src} → {packet[scapy.IP].dst} "
        
        if packet.haslayer(scapy.TCP):
            summary += f"TCP {packet[scapy.TCP].sport} → {packet[scapy.TCP].dport}"
            # Check for HTTP
            if packet.haslayer(http.HTTPRequest):
                url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
                summary += f" HTTP: {url}"
                
        elif packet.haslayer(scapy.UDP):
            summary += f"UDP {packet[scapy.UDP].sport} → {packet[scapy.UDP].dport}"
            # Check for DNS
            if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSQR):
                try:
                    qname = packet[scapy.DNSQR].qname.decode()
                    summary += f" DNS: {qname}"
                except:
                    pass
                
        elif packet.haslayer(scapy.ICMP):
            summary += f"ICMP type={packet[scapy.ICMP].type}"
    else:
        # Non-IP packet (e.g., ARP)
        summary += packet.summary()
    
    print(summary)

def print_statistics():
    """Print packet capture statistics"""
    with stats_lock:
        stats = packet_counts.copy()
        top_src_ips = src_ips.most_common(5)
        top_dst_ips = dst_ips.most_common(5)
        top_ports = (src_ports + dst_ports).most_common(5)
        top_protocols = protocols.most_common()
    
    print("\n===== Packet Capture Statistics =====")
    print(f"Total packets: {stats['total']}")
    print(f"TCP: {stats['tcp']}, UDP: {stats['udp']}, ICMP: {stats['icmp']}")
    print(f"DNS: {stats['dns']}, HTTP: {stats['http']}")
    
    print("\nTop source IPs:")
    for ip, count in top_src_ips:
        print(f"  {ip}: {count} packets")
    
    print("\nTop destination IPs:")
    for ip, count in top_dst_ips:
        print(f"  {ip}: {count} packets")
    
    print("\nTop ports:")
    for port, count in top_ports:
        print(f"  {port}: {count} packets")
    
    print("\nProtocols:")
    for proto, count in top_protocols:
        print(f"  {proto}: {count} packets")

def stop_sniffing_thread(duration, sniffer_thread):
    """Thread to stop sniffing after duration"""
    time.sleep(duration)
    # This will only work correctly on Windows
    if sniffer_thread.is_alive():
        # Send a keyboard interrupt to the main thread
        print("\nCapture duration reached. Stopping...")
        # This uses Windows-specific approach to interrupt the sniffer
        # Not ideal but works for this application
        import os
        os.kill(os.getpid(), 9)

def sniff_packets(interface, duration=10, packet_count=None, filter_str=None):
    """Sniff packets on the specified interface"""
    print(f"\nStarting packet capture on {interface}")
    print(f"Duration: {duration} seconds")
    if filter_str:
        print(f"Filter: {filter_str}")
    
    print("\nCapturing packets... Press Ctrl+C to stop")
    
    # Create a thread to stop sniffing after duration
    sniffer_thread = threading.current_thread()
    stop_thread = threading.Thread(target=stop_sniffing_thread, 
                                 args=(duration, sniffer_thread))
    stop_thread.daemon = True
    stop_thread.start()
    
    try:
        # Start the sniffer
        scapy.sniff(iface=interface, 
                   count=packet_count,
                   prn=packet_callback,
                   filter=filter_str,
                   store=0)  # Don't store packets in memory (we do it manually)
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
    except Exception as e:
        print(f"\nError during capture: {e}")
    finally:
        print_statistics()
        return captured_packets

def start_network_sniffer():
    """Start the network sniffer module"""
    print("\n--- Starting Network Sniffer (Scapy version) ---")
    
    # Get available interfaces
    interfaces = get_interfaces()
    
    if not interfaces:
        print("No network interfaces found!")
        return
    
    # Get local IP to help identify the right interface
    local_ip = get_local_ip()
    print(f"Your local IP address appears to be: {local_ip}")
    
    # Display available interfaces
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i+1}. {iface}")
    
    # Get user selection
    while True:
        try:
            choice = input("\nSelect interface number (or enter name directly): ")
            
            # Check if input is a number for selection
            if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
                interface = interfaces[int(choice) - 1]
                break
            # Otherwise, treat as direct interface name
            elif choice in interfaces:
                interface = choice
                break
            else:
                print("Invalid selection. Please try again.")
        except (ValueError, IndexError):
            print("Invalid input. Please enter a valid number or interface name.")
    
    # Get capture duration
    try:
        duration = int(input("Enter capture duration in seconds (default: 30): ") or "30")
    except ValueError:
        duration = 30
        print("Invalid input. Using default duration of 30 seconds.")
    
    # Get optional BPF filter
    filter_str = input("Enter capture filter (e.g., 'tcp port 80' or 'host 192.168.1.1') or leave empty: ")
    
    # Start packet capture
    try:
        print(f"\nStarting capture on interface '{interface}'...")
        print("You may need to generate some network traffic to see results.")
        print("Press Ctrl+C to stop capture early.")
        
        # Start sniffing
        sniff_packets(interface, duration, filter_str=filter_str)
        
    except Exception as e:
        print(f"Error: {e}")
    
    input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    # For testing this module directly
    start_network_sniffer()
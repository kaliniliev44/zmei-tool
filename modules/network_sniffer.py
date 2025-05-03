import pyshark
import time
import threading
import socket
import collections
from datetime import datetime
import sys
import os
import subprocess

# Store capture statistics
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

# Flag to control the capture process
stop_capture = threading.Event()

# Path to tshark executable
TSHARK_PATH = None

def find_tshark_path():
    """Find the tshark.exe path on Windows"""
    global TSHARK_PATH
    
    # First check if it's in PATH
    try:
        # Try to run tshark directly
        result = subprocess.run(
            ["tshark", "--version"], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            # Found in PATH
            TSHARK_PATH = "tshark"
            return True
    except:
        pass
    
    # If not in PATH, search common installation directories
    if os.name == 'nt':  # Windows
        # Common installation paths
        common_paths = [
            "C:\\Program Files\\Wireshark\\tshark.exe",
            "C:\\Program Files (x86)\Wireshark\\tshark.exe",
            "C:\\Wireshark\\tshark.exe",
            "D:\\Wireshark\\tshark.exe",
        ]
        
        # Search registry for Wireshark installation path
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WiresharkGroup\Wireshark") as key:
                install_dir, _ = winreg.QueryValueEx(key, "InstallDir")
                common_paths.insert(0, os.path.join(install_dir, "tshark.exe"))
        except:
            pass
            
        # Check if any of the common paths exist
        for path in common_paths:
            if os.path.exists(path):
                TSHARK_PATH = path
                return True
                
        # If not found in common paths, try searching Program Files directories
        for root_dir in [r"C:\Program Files", r"C:\Program Files (x86)"]:
            if os.path.exists(root_dir):
                for dir_name in os.listdir(root_dir):
                    if "wireshark" in dir_name.lower():
                        candidate = os.path.join(root_dir, dir_name, "tshark.exe")
                        if os.path.exists(candidate):
                            TSHARK_PATH = candidate
                            return True
    else:  # Unix/Linux/Mac
        # Check common Unix paths
        common_paths = [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/wireshark/bin/tshark"
        ]
        for path in common_paths:
            if os.path.exists(path):
                TSHARK_PATH = path
                return True
    
    return False

def get_interfaces():
    """Get list of available network interfaces using pyshark"""
    global TSHARK_PATH
    try:
        # This uses tshark to get interfaces, using the path we found
        if TSHARK_PATH and TSHARK_PATH != "tshark":
            # We need to set the path for pyshark to use
            os.environ['PATH'] = os.environ.get('PATH', '') + os.pathsep + os.path.dirname(TSHARK_PATH)
            
        tshark_interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
        return [interface['name'] for interface in tshark_interfaces]
    except Exception as e:
        print(f"Error getting interfaces from tshark: {e}")
        # Fallback to OS-specific methods
        if os.name == 'nt':  # Windows
            # Get network interfaces from ipconfig
            try:
                result = subprocess.run(
                    ["ipconfig"], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    text=True
                )
                if result.returncode == 0:
                    interfaces = []
                    for line in result.stdout.split('\n'):
                        if "adapter" in line and ":" in line:
                            # Extract adapter name
                            adapter_name = line.split(':')[0].strip()
                            interfaces.append(adapter_name)
                    if interfaces:
                        return interfaces
            except:
                pass
            
            # Last resort for Windows
            return ["Ethernet", "Wi-Fi", "Local Area Connection", "Wireless Network Connection"]
        else:
            # Fallback for Unix-like systems
            return ["eth0", "wlan0", "en0", "en1"]

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

def print_packet_summary(packet):
    """Print a summary of the packet"""
    # Get current timestamp
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    summary = f"[{timestamp}] "
    
    # Extract packet information
    try:
        # Check if packet has IP layer
        if hasattr(packet, 'ip'):
            summary += f"{packet.ip.src} → {packet.ip.dst} "
            
            if hasattr(packet, 'tcp'):
                summary += f"TCP {packet.tcp.srcport} → {packet.tcp.dstport}"
                # Check for HTTP
                if hasattr(packet, 'http'):
                    try:
                        if hasattr(packet.http, 'host') and hasattr(packet.http, 'request_uri'):
                            url = packet.http.host + packet.http.request_uri
                            summary += f" HTTP: {url}"
                        else:
                            summary += " HTTP"
                    except:
                        summary += " HTTP"
                    
            elif hasattr(packet, 'udp'):
                summary += f"UDP {packet.udp.srcport} → {packet.udp.dstport}"
                # Check for DNS
                if hasattr(packet, 'dns'):
                    try:
                        if hasattr(packet.dns, 'qry_name'):
                            summary += f" DNS: {packet.dns.qry_name}"
                        else:
                            summary += " DNS"
                    except:
                        summary += " DNS"
                    
            elif hasattr(packet, 'icmp'):
                summary += f"ICMP type={packet.icmp.type}"
                
        else:
            # Extract the highest layer as the protocol
            highest_layer = packet.highest_layer
            summary += f"{highest_layer} packet: {packet}"
    except Exception as e:
        summary += f"Error parsing packet: {e}"
    
    print(summary)
    sys.stdout.flush()  # Force flush output

def process_packet(packet):
    """Process each captured packet"""
    global packet_counts
    
    # Skip incomplete packets
    if not packet:
        return
    
    with stats_lock:
        packet_counts['total'] += 1
        
        # Identify packet type and update counters
        if hasattr(packet, 'tcp'):
            packet_counts['tcp'] += 1
            protocols['TCP'] += 1
            if hasattr(packet, 'ip'):
                src_ips[packet.ip.src] += 1
                dst_ips[packet.ip.dst] += 1
                src_ports[f"TCP:{packet.tcp.srcport}"] += 1
                dst_ports[f"TCP:{packet.tcp.dstport}"] += 1
        
        elif hasattr(packet, 'udp'):
            packet_counts['udp'] += 1
            protocols['UDP'] += 1
            if hasattr(packet, 'ip'):
                src_ips[packet.ip.src] += 1
                dst_ips[packet.ip.dst] += 1
                src_ports[f"UDP:{packet.udp.srcport}"] += 1
                dst_ports[f"UDP:{packet.udp.dstport}"] += 1
        
        elif hasattr(packet, 'icmp'):
            packet_counts['icmp'] += 1
            protocols['ICMP'] += 1
        
        # Check for DNS packets
        if hasattr(packet, 'dns'):
            packet_counts['dns'] += 1
            protocols['DNS'] += 1
        
        # Check for HTTP packets
        if hasattr(packet, 'http'):
            packet_counts['http'] += 1
            protocols['HTTP'] += 1
    
    # Print the packet summary
    print_packet_summary(packet)

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

def capture_live_packets(interface, duration=30, bpf_filter=None):
    """Capture live packets using pyshark"""
    global stop_capture, TSHARK_PATH
    stop_capture.clear()
    
    print(f"\nStarting packet capture on {interface}")
    print(f"Duration: {duration} seconds")
    if bpf_filter:
        print(f"Filter: {bpf_filter}")
    
    print("\nCapturing packets... Press Ctrl+C to stop")
    
    # Reset packet counters
    global packet_counts, src_ips, dst_ips, src_ports, dst_ports, protocols
    packet_counts = {
        'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'dns': 0, 'http': 0, 'other': 0
    }
    src_ips.clear()
    dst_ips.clear()
    src_ports.clear()
    dst_ports.clear()
    protocols.clear()
    
    # Start a timer to stop capture after duration
    def stop_timer():
        time.sleep(duration)
        print("\nCapture duration reached. Stopping...")
        stop_capture.set()
    
    timer_thread = threading.Thread(target=stop_timer)
    timer_thread.daemon = True
    timer_thread.start()
    
    # Start capturing
    try:
        # Configure capture options
        capture_options = {
            'interface': interface,
            'display_filter': bpf_filter
        }
        
        # If we found tshark path and it's not the default, set it
        if TSHARK_PATH and TSHARK_PATH != "tshark":
            # For pyshark to use our tshark path, we modify the environment PATH
            os.environ['PATH'] = os.path.dirname(TSHARK_PATH) + os.pathsep + os.environ.get('PATH', '')
            
            # Some pyshark versions allow setting tshark path directly
            try:
                capture_options['tshark_path'] = TSHARK_PATH
            except:
                pass
        
        # Create capture
        capture = pyshark.LiveCapture(**capture_options)
        
        # Set the sniff timeout to 1 second so we can check the stop flag
        capture.sniff_timeout = 1
        
        # Start sniffing in a loop, checking the stop flag
        start_time = time.time()
        while not stop_capture.is_set() and time.time() - start_time < duration:
            try:
                # Capture packets for a short duration
                for packet in capture.sniff_continuously(packet_count=10):
                    if stop_capture.is_set():
                        break
                    process_packet(packet)
            except Exception as e:
                print(f"Error during capture: {e}")
                time.sleep(0.1)  # Prevent tight loop if errors occur
    
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except Exception as e:
        print(f"\nError during capture: {e}")
    finally:
        stop_capture.set()
        print_statistics()

def check_wireshark_installation():
    """Check if Wireshark/tshark is installed and accessible"""
    global TSHARK_PATH
    
    # Try to find tshark path
    if find_tshark_path():
        # Run tshark to get version
        try:
            if TSHARK_PATH == "tshark":
                cmd = ["tshark", "--version"]
            else:
                cmd = [TSHARK_PATH, "--version"]
                
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                version_info = result.stdout.split('\n')[0]
                print(f"Wireshark/tshark found: {version_info}")
                print(f"Using tshark at: {TSHARK_PATH}")
                return True
            else:
                print(f"Wireshark/tshark found at {TSHARK_PATH} but returned an error")
                return False
        except Exception as e:
            print(f"Error running tshark: {e}")
            return False
    else:
        print("Wireshark/tshark not found on this system")
        return False

def check_admin():
    """Check if the script is running with admin/root privileges"""
    try:
        is_admin = False
        if os.name == 'nt':  # Windows
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix/Linux/Mac
            is_admin = os.geteuid() == 0
        return is_admin
    except:
        return False

def start_network_sniffer():
    """Start the network sniffer module using pyshark"""
    print("\n--- Starting Network Sniffer (Wireshark/pyshark version) ---")
    
    # Check admin privileges
    if not check_admin():
        print("\nWARNING: This script may not work correctly without administrator/root privileges.")
        print("For best results, please run this program with elevated privileges.")
        print("On Windows: Right-click and select 'Run as administrator'")
        print("On Linux/Mac: Use 'sudo python main.py'\n")
    
    # Check if Wireshark is installed
    if not check_wireshark_installation():
        print("\nUnable to find Wireshark/tshark which is required for this module.")
        print("Please install Wireshark from: https://www.wireshark.org/download.html")
        input("\nPress Enter to return to main menu...")
        return
    
    # Get available interfaces
    interfaces = get_interfaces()
    
    if not interfaces:
        print("No network interfaces found!")
        input("\nPress Enter to return to main menu...")
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
    
    # Get optional display filter
    filter_str = input("Enter capture filter (e.g., 'tcp port 80' or 'host 192.168.1.1') or leave empty: ")
    if not filter_str.strip():
        filter_str = None
    
    # Start packet capture
    try:
        print(f"\nStarting capture on interface '{interface}'...")
        print("You may need to generate some network traffic to see results.")
        print("Press Ctrl+C to stop capture early.")
        
        # Start capturing
        capture_live_packets(interface, duration, filter_str)
        
    except Exception as e:
        print(f"Error: {e}")
    
    input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    # For testing this module directly
    start_network_sniffer()
# Updated port_scanner.py with configurable threading

import socket
import threading
import queue

def scan_port(target, port, timeout=1):
    """
    Scan a single port on the target IP address.
    """
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for the connection attempt
        sock.settimeout(timeout)
        # Attempt to connect to the target IP and port
        result = sock.connect_ex((target, port))
        # If the result is 0, the port is open
        if result == 0:
            print(f"Port {port} is open")
            return True
        else:
            print(f"Port {port} is closed")
            return False
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return False
    finally:
        # Close the socket
        sock.close()


def scan_port_with_lock(target, port, lock, verbose=True, timeout=1):
    """
    Thread-safe version of scan_port using a lock for printing
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        
        # Only print if port is open or if verbose mode is on
        if result == 0:
            lock.acquire()
            print(f"Port {port} is open")
            lock.release()
            return True
        elif verbose:
            lock.acquire()
            print(f"Port {port} is closed")
            lock.release()
        return False
    except Exception as e:
        if verbose:
            lock.acquire()
            print(f"Error scanning port {port}: {e}")
            lock.release()
        return False
    finally:
        sock.close()


def scan_port_range(target, start_port, end_port, thread_count=100, verbose=True, timeout=1):
    """
    Scan a range of ports on the target IP address using multiple threads.
    
    Parameters:
    - target: Target IP address to scan
    - start_port: Starting port number
    - end_port: Ending port number
    - thread_count: Number of threads to use (default: 100)
    - verbose: Whether to print closed ports (default: True)
    - timeout: Socket connection timeout in seconds (default: 1)
    
    Returns:
    - List of open ports
    """
    # Create a queue to hold all ports
    port_queue = queue.Queue()
    
    # Create a lock for synchronized printing
    print_lock = threading.Lock()
    
    # List to store open ports
    open_ports = []
    open_ports_lock = threading.Lock()
    
    # Define the threader function
    def threader():
        while True:
            # Get port from queue (blocks until one is available)
            port = port_queue.get()
            
            # Scan the port
            is_open = scan_port_with_lock(target, port, print_lock, verbose, timeout)
            
            # Add to open ports list if open
            if is_open:
                with open_ports_lock:
                    open_ports.append(port)

            # Signal task completion
            port_queue.task_done()
    
    # Fill the queue with ports to scan
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
    
    print(f"Starting scan of {target} with {thread_count} threads...")
    print(f"Scanning ports {start_port} to {end_port} ({end_port - start_port + 1} ports total)")
    
    # Start the worker threads
    threads = []
    for _ in range(min(thread_count, end_port - start_port + 1)):
        thread = threading.Thread(target=threader)
        thread.daemon = True  # Thread dies when main thread exits
        thread.start()
        threads.append(thread)
    
    # Wait for all ports to be scanned
    port_queue.join()
    
    # Print summary
    print(f"Scan complete: {end_port - start_port + 1} ports scanned on {target}")
    if open_ports:
        print(f"Found {len(open_ports)} open ports: {sorted(open_ports)}")
    else:
        print("No open ports found.")
    
    return sorted(open_ports)


# Example of more configurable scan functions
def quick_scan(target, common_ports=[21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]):
    """
    Quickly scan the most common ports
    """
    print(f"Quick scan of most common ports on {target}")
    open_ports = []
    for port in common_ports:
        if scan_port(target, port):
            open_ports.append(port)
    return open_ports


def stealth_scan(target, start_port, end_port, thread_count=20, timeout=2):
    """
    Slower, more stealthy scan with fewer threads and longer timeouts
    """
    print(f"Starting stealth scan of {target}...")
    return scan_port_range(target, start_port, end_port, thread_count, verbose=False, timeout=timeout)


def aggressive_scan(target, start_port, end_port, thread_count=500, timeout=0.5):
    """
    Fast scan with many threads and shorter timeouts
    """
    print(f"Starting aggressive scan of {target}...")
    return scan_port_range(target, start_port, end_port, thread_count, verbose=True, timeout=timeout)
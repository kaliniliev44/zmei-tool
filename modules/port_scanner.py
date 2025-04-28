import socket
import threading
import queue

port_queue = queue.Queue()



def scan_port(target, port):
    """
    Scan a single port on the target IP address.
    """
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for the connection attempt
        sock.settimeout(1)
        # Attempt to connect to the target IP and port
        result = sock.connect_ex((target, port))
        # If the result is 0, the port is open
        if result == 0:
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
    finally:
        # Close the socket
        sock.close()


def scan_port_with_lock(target, port, lock):
    """
    Thread-safe version of scan_port using a lock for printing
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        
        # Only print if port is open
        if result == 0:
            lock.acquire()
            print(f"Port {port} is open")
            lock.release()
    except Exception as e:
        lock.acquire()
        print(f"Error scanning port {port}: {e}")
        lock.release()
    finally:
        sock.close()


def scan_port_range(target, start_port, end_port, thread_count=100):
    """
    Scan a range of ports on the target IP address using multiple threads.
    """
    # Create a queue to hold all ports
    port_queue = queue.Queue()
    
    # Create a lock for synchronized printing
    print_lock = threading.Lock()
    
    # Define the threader function within scan_port_range to access target and lock
    def threader():
        while True:
            # Get port from queue (blocks until one is available)
            port = port_queue.get()
            # Scan the port
            scan_port_with_lock(target, port, print_lock)

            # Signal task completion
            port_queue.task_done()
    
    # Fill the queue with ports to scan
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
    
    # Start the worker threads
    for _ in range(thread_count):
        thread = threading.Thread(target=threader)
        thread.daemon = True  # Thread dies when main thread exits
        thread.start()
    
    # Wait for all ports to be scanned
    port_queue.join()
    print(f"Scan complete: {end_port - start_port + 1} ports scanned on {target}")

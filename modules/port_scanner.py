import socket
import threading


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
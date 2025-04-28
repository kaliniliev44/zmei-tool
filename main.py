from modules import port_scanner, network_sniffer

def main():
    print("Zmei - Python SOC Toolkit")
    print("Version 1.0")
    print("Tools:")
    print("0. Help")
    print("1. Port Scanner (single port)")
    print("2. Port Scanner (multi port)")
    print("3. Port Scanner (quick scan)")
    print("4. Port Scanner (stealth scan)")
    print("5. Port Scanner (aggressive scan)")
    print("6. Network Sniffer")

    # update the tools list as needed
    tools = {
        "1": "Port Scanner (single port)",
        "2": "Port Scanner (multi port)",
        "3": "Port Scanner (quick scan - common ports)",
        "4": "Port Scanner (stealth scan - slower, less detectable)",
        "5": "Port Scanner (aggressive scan - faster, more threads)",
        "6": "Network Sniffer",
    }

    while True:
        choice = input("\nSelect a tool (0-6) or 'q' to quit: ")
        if choice == 'q':
            print("Exiting...")
            break
        elif choice in tools:
            print(f"You selected: {tools[choice]}")
            
            if choice in ['1', '2', '3', '4', '5']:  # All port scanning options
                target_ip = input("Enter target IP address: ")
                
                if choice == '1':  # Single port scan
                    port = int(input("Enter port number to scan: "))
                    timeout = float(input("Enter timeout in seconds (default: 1): ") or "1")
                    port_scanner.scan_port(target_ip, port, timeout)
                
                elif choice == '2':  # Multi-port scan with configurable threads
                    start_port = int(input("Enter starting port number: "))
                    end_port = int(input("Enter ending port number: "))
                    thread_count = int(input("Enter number of threads (default: 100): ") or "100")
                    verbose = input("Show closed ports? (y/n, default: n): ").lower() == 'y'
                    timeout = float(input("Enter timeout in seconds (default: 1): ") or "1")
                    
                    port_scanner.scan_port_range(
                        target_ip, 
                        start_port, 
                        end_port, 
                        thread_count=thread_count,
                        verbose=verbose,
                        timeout=timeout
                    )
                
                elif choice == '3':  # Quick scan
                    port_scanner.quick_scan(target_ip)
                
                elif choice == '4':  # Stealth scan
                    start_port = int(input("Enter starting port number: "))
                    end_port = int(input("Enter ending port number: "))
                    thread_count = int(input("Enter number of threads (default: 20): ") or "20")
                    timeout = float(input("Enter timeout in seconds (default: 2): ") or "2")
                    
                    port_scanner.stealth_scan(
                        target_ip,
                        start_port,
                        end_port,
                        thread_count=thread_count,
                        timeout=timeout
                    )
                
                elif choice == '5':  # Aggressive scan
                    start_port = int(input("Enter starting port number: "))
                    end_port = int(input("Enter ending port number: "))
                    thread_count = int(input("Enter number of threads (default: 500): ") or "500")
                    timeout = float(input("Enter timeout in seconds (default: 0.5): ") or "0.5")
                    
                    port_scanner.aggressive_scan(
                        target_ip,
                        start_port,
                        end_port,
                        thread_count=thread_count,
                        timeout=timeout
                    )
            
            elif choice == '6':  # Network Sniffer
                network_sniffer.start_network_sniffer()
            
        elif choice == '0':
            print("\nHelp:")
            print("1. Port Scanner (single port): Scans a single port on a target IP address.")
            print("2. Port Scanner (multi port): Scans a range of ports on a target IP address.")
            print("3. Port Scanner (quick scan): Quickly scans common ports on a target IP.")
            print("4. Port Scanner (stealth scan): Slow, less detectable scan with fewer threads.")
            print("5. Port Scanner (aggressive scan): Fast scan with many threads.")
            print("6. Network Sniffer: Captures and analyzes network packets.")
            print("q. Quit: Exit the program.")
        else:
            print("Invalid choice. Please try again.")
    

if __name__ == "__main__":
    main()
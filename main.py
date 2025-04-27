from modules import port_scanner

def main():
    print("Zmei - Python SOC Toolkit")
    print("Version 1.0")
    print("Tools:")
    print("0. Help")
    print("1. Port Scanner")
    print("2. Network Sniffer")

    # update the tools list as needed
    tools = {
        "1": "Port Scanner(single port)",
        "2": "Port Scanner(multi port)",
        "3": "Network Sniffer",
    }

    while True:
        choice = input("Select a tool (1-3) or 'q' to quit: ")
        if choice == 'q':
            print("Exiting...")
            break
        elif choice in tools:
            print(f"You selected: {tools[choice]}")
            match choice:
                case '1':
                    # Call the port scanner function for a single port
                    target_ip = input("Enter target IP address: ")
                    port = int(input("Enter port number to scan: "))
                    port_scanner.scan_port(target_ip, port)
                case '2':
                    # Call the port scanner function for a range of ports
                    target_ip = input("Enter target IP address: ")
                    start_port = int(input("Enter starting port number: "))
                    end_port = int(input("Enter ending port number: "))
                    # Implement the multi-port scanning logic here
            
        elif choice == '0':
            print("Help:")
            print("1. Port Scanner: Scans a range of ports on a target IP address.")
            print("2. Port Scanner (single port): Scans a single port on a target IP address.")
            print("3. Network Sniffer: Captures and analyzes network packets.")
            print("q. Quit: Exit the program.")
        else:
            print("Invalid choice. Please try again.")
    

if __name__ == "__main__":
    main()


def main():
    print("Zmei - Python SOC Toolkit")
    print("Version 1.0")
    print("Tools:")
    print("0. Help")
    print("1. Port Scanner")
    print("2. Network Sniffer")

    # update the tools list as needed
    tools = {
        "1": "Port Scanner",
        "2": "Network Sniffer",
    }

    while True:
        choice = input("Select a tool (1-2) or 'q' to quit: ")
        if choice == 'q':
            print("Exiting...")
            break
        elif choice in tools:
            print(f"You selected: {tools[choice]}")
            # Call the corresponding function here
            # For example, if you implement port scanner, call it here
        elif choice == '0':
            print("Help:")
            print("1. Port Scanner: Scans a range of ports on a target IP address.")
            print("2. Network Sniffer: Captures and analyzes network packets.")
            print("q. Quit: Exit the program.")
        else:
            print("Invalid choice. Please try again.")
    

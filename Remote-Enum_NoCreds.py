#!/usr/bin/env python3
import re
import sys
import os
import requests  # Add this import

#sudo cp your_script.py /usr/local/bin/your_script
#sudo chmod +x /usr/local/bin/your_script

# Dictionary to store commands organized by port
port_commands = {}

# Read commands from the text file (now fetched via HTTP)
commands_file_url = 'https://raw.githubusercontent.com/wireshocks/RemoteEnum/refs/heads/main/commands_NoCreds.txt'
try:
    # Download the file instead of opening it directly
    response = requests.get(commands_file_url)
    response.raise_for_status()  # Check for HTTP errors
    
    current_port = None
    for line in response.text.split('\n'):
        line = line.strip()
        if not line:
            continue
        port_match = re.match(r'^### Port (\d+)', line)
        if port_match:
            current_port = port_match.group(1)
            port_commands[current_port] = []
        elif current_port and not line.startswith('#'):
            port_commands[current_port].append(line)
except requests.exceptions.RequestException as e:
    print(f"Error: Failed to fetch commands file from '{commands_file_url}'")
    print(f"Details: {e}")
    sys.exit(1)

def read_ports_file(filename):
    """Read ports from file and return as list"""
    try:
        with open(filename, 'r') as f:
            ports = []
            for line in f:
                # Remove comments and whitespace
                line = line.split('#')[0].strip()
                if line:  # Only add non-empty lines
                    ports.append(line)
            return ports
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

def replace_placeholders(command, ip_address, username, domain, shortdomain, computer_name):
    """Replace placeholders in the command with provided values if present"""
    replacements = {
        "$rhost": ip_address,
        "$user": username,
        "$domain": domain,
        "$shortdomain": shortdomain,
        "$computer_name": computer_name
    }
    
    for placeholder, value in replacements.items():
        if placeholder in command and value:  # Only replace if value is provided
            command = command.replace(placeholder, value)
    return command

def generate_scripts(commands, ip_address, username, domain, shortdomain, computer_name):
    """Generate Bash script with all commands"""
    timestamp = re.sub(r'[^\w]', '_', f"{ip_address or 'target'}_{domain or 'domain'}")
    sh_filename = f"NoCreds_{timestamp}.sh"
    
    sh_content = """#!/bin/bash

echo "Remote Enumeration Script"
echo "Author: Muharram Ali"
echo "Email: ali.oscp@proton.me"
echo "Version: 2025.1"
echo ""

# Function to edit command
edit_command() {
    local cmd="$1"
    echo -e "\\nCurrent command: $cmd"
    read -p "Edit command (leave empty to keep current): " new_cmd
    if [ -n "$new_cmd" ]; then
        echo "$new_cmd"
    else
        echo "$cmd"
    fi
}

# Function to prompt for command execution
prompt_and_run() {
    local cmd="$1"
    echo -e "\\n===== Next command: ============================================================================\\n$cmd"
    while true; do
        read -p "Execute this command? (Y/N/E/S): " yn
        case $yn in
            [Yy]* ) 
                echo "Executing..."
                eval "$cmd"
                break
                ;;
            [Nn]* ) 
                echo "Skipping..."
                break
                ;;
            [Ee]* )
                cmd=$(edit_command "$cmd")
                continue
                ;;
            [Ss]* ) 
                echo "Stopping script..."
                exit 0
                ;;
            * ) 
                echo "Please answer Y (yes), N (no), E (edit), or S (stop)."
                ;;
        esac
    done
}

# Generated commands
"""
    
    for cmd in commands:
        escaped_cmd = cmd.replace('"', '\\"')
        sh_content += f'prompt_and_run "{escaped_cmd}"\n'
    
    with open(sh_filename, 'w') as f:
        f.write(sh_content)
    os.chmod(sh_filename, 0o755)
    
    print(f"\nGenerated Bash script: {sh_filename}")
    print("\nYou can execute it with: bash {sh_filename}")
    print("\nThe Bash script will prompt you before each command (Y/N/E/S):")
    print("- Y: Yes, execute this command")
    print("- N: No, skip this command")
    print("- E: Edit this command before executing")
    print("- S: Stop the entire script")

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} ports-IP.log")
        sys.exit(1)
    
    # Ask for connection details
    ip_address = input("Enter target IP address (or press Enter to skip): ").strip()
    username = input("Enter username (or press Enter to skip): ").strip()
    computer_name = input("Enter computer name (or press Enter to skip): ").strip()
    domain = input("Enter full domain (e.g., contoso.com) or press Enter to skip: ").strip()
    shortdomain = input("Enter short domain (e.g., contoso) or press Enter to skip: ").strip()
    
    ports_file = sys.argv[1]
    target_ports = read_ports_file(ports_file)
    
    print(f"\n### Commands for ports: {', '.join(target_ports)} ###")
    if ip_address:
        print(f"### Target IP: {ip_address} ###")
    else:
        print("### No target IP provided - commands with $rhost will be shown as-is ###")
    if username:
        print(f"### Username: {username} ###")
    else:
        print("### No username provided - commands with $user will be shown as-is ###")
    if computer_name:
        print(f"### Computer Name: {computer_name} ###")
    else:
        print("### No computer name provided - commands with $computer_name will be shown as-is ###")
    if domain:
        print(f"### Domain: {domain} ###")
    else:
        print("### No domain provided - commands with $domain will be shown as-is ###")
    if shortdomain:
        print(f"### Short Domain: {shortdomain} ###\n")
    else:
        print("### No short domain provided - commands with $shortdomain will be shown as-is ###\n")
    
    found_any = False
    all_commands = []
    for port in target_ports:
        if port in port_commands:
            found_any = True
            for cmd in port_commands[port]:
                cmd = replace_placeholders(cmd, ip_address, username, domain, shortdomain, computer_name)
                all_commands.append(cmd)
    
    if not found_any:
        print("No commands found for the specified ports.")
        sys.exit(1)
    
    # Generate executable Bash script
    generate_scripts(all_commands, ip_address, username, domain, shortdomain, computer_name)

if __name__ == "__main__":
    main()

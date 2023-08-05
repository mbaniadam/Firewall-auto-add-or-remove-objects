This Python script allows you to manage IP address objects in multi-vendor firewalls, including FortiGate, Juniper Junos, ScreenOS, and Sophos. It leverages Netmiko for SSH-based communication and uses REST API tokens for Sophos firewalls. The tool prompts you to enter your choice for either adding an IP address to an address group or removing an IP address from a group.

Features
Add IP address objects to firewall address groups.
Remove IP address objects from firewall address groups.
Support for FortiGate, Juniper Junos, ScreenOS, and Sophos firewalls.
Simple configuration using YAML and CSV files.
Error handling and validation for existing address groups.
Prerequisites
Before running the script, ensure you have the following prerequisites:

Python 3.x installed on your system.
The necessary Python libraries installed (netmiko, requests, csv, yaml).
Getting Started
Clone the repository:
bash
Copy code
git clone https://github.com/mbaniadam/Firewall-auto-add-or-remove-objects.git
Install the required dependencies:

pip install netmiko requests
Update the inventory.yml file:

This file will contain the necessary credentials for each firewall.
Modify the file and add the host address, port, username, password, or token for each firewall.
Prepare the IP_LIST.csv file:

This CSV file will contain the IP addresses, their naming conventions, and the address groups they should be added to or removed from.
Follow the given format in the example below:
csv
Copy code
IP Address,Convention,Group
192.168.1.10,Server_,Web-Servers
10.0.2.20,Printer_,Office-Devices
In this example, we add 192.168.1.10 with the name Server_192.168.1.10/32 to the Web-Servers group, and we add 10.0.2.20 with the name Printer_10.0.2.20/32 from the Office Devices group.
**NOTE** 
IP address  without CIDR (example: 192.168.1.0 **/24**) will assumed /32.
#### Usage
To run the script, use the following command:

python3 firewall_management.py
The script will prompt you to choose the action you want to perform:

Add IP address to an address group: If you choose this option, the script will read the IP_LIST.csv file and add the specified IP addresses to the corresponding firewall address groups.

Remove IP address from an address group: If you choose this option, the script will read the IP_LIST.csv file and remove the specified IP addresses from the respective firewall address groups.

Please ensure that the address groups mentioned in the IP_LIST.csv file already exist on your firewalls.

Important Notes
Be cautious when using this tool, as it directly modifies the firewall configurations.
Always backup your firewall configurations before running the script.
Contributing
We welcome contributions to improve this tool and add support for more firewall vendors. If you find any issues or have suggestions for enhancements, feel free to open an issue or submit a pull request.


Disclaimer
The authors of this tool are not responsible for any damage or loss caused by using this tool. Use it at your own risk and always verify the changes made to your firewall configurations.

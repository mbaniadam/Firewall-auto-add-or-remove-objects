## Add or Remove IP addresses to address groups in multivendor firewalls and Fortinet policy finder


This Python script allows you to manage IP address objects in multi-vendor firewalls, including FortiGate, Juniper Junos, ScreenOS, and Sophos. It leverages Netmiko for SSH-based communication and uses REST API tokens for Sophos firewalls. The tool prompts you to enter your choice for either adding an IP address to an address group or removing an IP address from a group.

### Features
- Add IP address objects to firewall address groups.

- Remove IP address objects from firewall address groups.

- Error handling and validation for existing address groups.

- Find Fortinet policies related to an IP address.

- IP validation.

- Support multivendor firewalls


**API Method**
* [x] FortiGate
* [x] Sophos

**SSH Method**
* [x] Juniper JunOS
* [x] Juniper ScreenOS


### Prerequisites
Before running the script, ensure you have the following prerequisites:

Python 3.x installed on your system.

The necessary Python libraries installed (netmiko, requests, csv, yaml, json, ipaddress, re).

### Getting Started
Clone the repository:

```console bash
git clone https://github.com/mbaniadam/Firewall-auto-add-or-remove-objects.git
```
Install the required dependencies:
```console bash
pip install netmiko requests
```
Update the inventory.yml file:

This file will contain the necessary credentials for each firewall.
Modify the file and add the host address, port, username, password, or token for each firewall.
Prepare the IP_LIST.csv file:

This CSV file will contain the IP addresses, their naming conventions, and the address groups they should be added to or removed from.
Follow the given format in the example below:

IP Address,Convention,Group

192.168.1.10,Server_,Web-Servers

10.0.2.20,Printer_,Office-Devices

In this example, we add 192.168.1.10 with the name Server_192.168.1.10/32 to the Web-Servers group, and we add 10.0.2.20 with the name Printer_10.0.2.20/32 from the Office Devices group.

**NOTE** 

IP address  without CIDR (example: 192.168.1.0 **/24**) will assumed /32.

#### Usage
To run the script, use the following command:

```console bash
python3 multivendor_add_remove_objects.py
```
The script will prompt you to choose the action you want to perform:

**Add IP address to an address group:** If you choose this option, the script will read the IP_LIST.csv file and add the specified IP addresses to the corresponding firewall address groups.

**Remove IP address from an address group:** If you choose this option, the script will read the IP_LIST.csv file and remove the specified IP addresses from the respective firewall address groups.

**Find Fortinet Policies Related to an IP Address:** This option allows you to find policies related to an IP address in Fortinet products. The script will iterate through the IP_LIST.csv file and then send a GET request to the firewall API specified in the inventory.yml file to retrieve the policies associated with the specified IP address.

Please ensure that the address groups mentioned in the IP_LIST.csv file already exist on your firewalls. If not, the script will display a message indicating that the address was not found and no policies could be retrieved."

### Important Notes
The script checks the validity of all IP addresses before making changes to the firewalls. However, be cautious when using this tool, as it directly modifies the firewall address groups.
Always check your address list before running the script.


### Contributing
If you find any issues or have suggestions for enhancements, feel free to open an issue or submit a pull request.

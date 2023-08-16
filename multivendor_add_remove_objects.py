
"""
This Python script allows you to manage IP address objects in multi-vendor firewalls,
including FortiGate, Juniper Junos, ScreenOS, and Sophos. It leverages Netmiko for SSH-based
communication and uses REST API tokens for Sophos firewalls. The tool prompts you to enter your
choice for either adding an IP address to an address group or removing an IP address from a group.
"""
import os
import ipaddress
import json
import re
from time import sleep
import csv
import urllib3
import requests
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import yaml


# import logging
# logging.basicConfig(filename='netmiko_global.log', level=logging.DEBUG)
# logger = logging.getLogger("netmiko")
# With the __file__ and os.path functions, you can change the current directory to the directory containing the running script file


os.chdir(os.path.dirname(os.path.abspath(__file__)))
path = os.getcwd()
print(path)


def read_yaml(yml_path="inventory.yml"):
    """
    Read and load content from a YAML file.

    This function reads the content from a specified YAML file and returns
    the loaded content as a Python dictionary.

    Args:
        path (str, optional): The path to the YAML file. Defaults to "inventory.yml".

    Returns:
        dict: A dictionary containing the loaded content from the YAML file.
    """
    with open(yml_path, encoding="utf-8") as f:
        yaml_content = yaml.safe_load(f.read())
        # print(yaml_content)
    return yaml_content


def word_count(target_word, input_data):
    """
    Count the occurrences of a target word in a given string.

    This function takes a target word and a string as input and counts
    the number of times the target word appears within the string.

    Args:
        target_word (str): The word to be counted.
        data (str): The input string to search within.

    Returns:
        int: The count of occurrences of the target word in the input string.
    """
    counts = 0
    words = input_data.split()
    for word in words:
        if target_word in word:
            counts += 1
    return counts


def is_host_in_subnet(subnet, input_ip):
    """
    Check if an IP address belongs to a given subnet.

    This function takes a subnet and an IP address as input and checks if
    the IP address is within the specified subnet.

    Args:
        subnet (str): The subnet in CIDR notation.
        ip (str): The IP address to check.

    Returns:
        str: The subnet if the IP address belongs to it, otherwise None.
    """
    try:
        if "0.0.0.0/0" not in subnet:
            subnet_network = ipaddress.IPv4Network(subnet, strict=False)
            input_ip = ipaddress.IPv4Network(input_ip, strict=False)
            if input_ip.subnet_of(subnet_network):
                return str(subnet)
        # else:
        #     print(f"{subnet} not allowed!")
        return None
    except ValueError:
        print(ValueError)


def valiadate_ip(input_ip):
    """
    Validate an IP address.

    This function takes an IP address as input and checks if it's a valid IP address.
    It also checks if the IP address is not APIPA or or "0.0.0.0/0".

    Args:
        ip (str): The IP address to validate.

    Returns:
        str: The validated IP address if it's valid, otherwise None.
    """
    try:
        print(f"-------------------------\nChecking {input_ip} ...")
        if input_ip == ("169.254.0.0", "0.0.0.0/0"):
            raise ValueError
        ip_interface = ipaddress.ip_interface(input_ip)
        # ip_cidr = ip_interface.with_netmask.split('/')[1]
        # pref_len = ip_interface.with_prefixlen.split('/')[1]
        if ip_interface:
            print(" IP:", input_ip, "is valid.")
            return str(ip_interface)
    except ValueError:
        print(" IP address is not valid!")


def make_api_request(url, method, headers=None, data=None):
    try:
        if method == 'GET':
            response = requests.get(
                url, verify=False, headers=headers, timeout=10)
        elif method == 'POST':
            response = requests.post(
                url, verify=False, headers=headers, data=data, timeout=10)
        elif method == 'DELETE':
            response = requests.delete(
                url, verify=False, headers=headers, data=data, timeout=10)
        else:
            raise ValueError("Invalid HTTP method")

        if response.status_code in (500, 404, 403):
            return response

        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as http_error:
        print(f"An error occurred: {http_error}")
        return None


def add_via_ssh(host, ip_dic_validated):
    print("**************************** Add via SSH ****************************")
    try:
        if host["device_type"] == "juniper_junos":
            logical_system = str(
                input(f"\n For VMOR >>> MORCO-Ls\
                \n For JMOR >>> MORCO\n Default: MORCO\n Enter logical-systems name for {host['host']} : ")
                or "MORCO")
            print(f">>> Looking in {host['host']} juniper_junos...")
            juniper_junos = ConnectHandler(**host)
            count = 0
            duplicate_member = 0
            number_of_created = 0
            changed = False
            objects_dic = {}
            objects2create_dic = {}
            # Get all address from address-book
            print(" Checking Addresses ...")
            address_check = f"show configuration logical-systems {logical_system} security address-book | display set"
            address_check_result = juniper_junos.send_command(
                address_check, expect_string=r">", read_timeout=40)
            print(" Checking Subnets ...")
            subnet_check = "show configuration logical-systems | match inet | display set"
            subnet_check_result = juniper_junos.send_command(
                subnet_check, expect_string=r">", read_timeout=40)
            print(" Checking Zone names ...")
            zone_check = f"show configuration logical-systems {logical_system} security zones | display set "
            zone_check_result = juniper_junos.send_command(
                zone_check, expect_string=r">", read_timeout=40)
            print(" Checking default route ...")
            gateway_check = f"show configuration logical-systems {logical_system} routing-instances | match 0.0.0.0/0 | display set"
            gateway_check_result = juniper_junos.send_command(
                gateway_check, expect_string=r">", read_timeout=40)
            gateway_ip = gateway_check_result.split()[-1]
            print(f" Found default route via {gateway_ip}")
            for line in subnet_check_result.splitlines():
                subnet4check = line.split(" ")[-1]
                # subnet4check_v4 = ipaddress.ip_interface(subnet4check)
                # subnet4check_net = subnet4check_v4.network
                subnet_checked = is_host_in_subnet(
                    subnet4check, gateway_ip)
                if subnet_checked:
                    interface_of_gw = line.split(" ")[4]
                    vlan_of_gw = line.split(" ")[6]
                    for line in zone_check_result.splitlines():
                        if f"{interface_of_gw}.{vlan_of_gw}" in line:
                            zone_untrust = line.split()[6]
                            print(f" Zone Untrust is: {zone_untrust}")
                            break
            for values, _ in ip_dic_validated.items():
                print("------- Address:", values)
                grp_name = ip_dic_validated[values][2]
                zone_name = ""
                ip_with_cidr = values
                ip_cidr = values.split('/')[1]
                founded_addr = list(filter(
                    lambda line: f" {ip_with_cidr}" in line, address_check_result.splitlines()))
                if founded_addr:
                    address_name = founded_addr[0].split(" ")[7]
                    zone_name = founded_addr[0].split(" ")[5]
                    objects_dic.update(
                        {ip_with_cidr: [address_name, zone_name, grp_name]})
                else:
                    untrust_check = "1"
                    ip_without_cidr = ip_with_cidr.split('/')[0]
                    convention = ip_dic_validated[values][0]
                    description = ip_dic_validated[values][1]
                    if (convention == "R_" or convention == "A_") and ip_cidr != "32":
                        address_name_4new = convention+ip_with_cidr
                    else:
                        address_name_4new = convention+ip_without_cidr
                    interface = ""
                    vlan = ""
                    # subnet_checker(subnet_check_result,ip_without_cidr)
                    # founded_addr = list(filter(lambda line: f" {ip_with_cidr}" in line, subnet_check_result.splitlines()))
                    for line in subnet_check_result.splitlines():
                        # get subnet at end of the line
                        inet_address = line.split(" ")[10]
                        # convert inet_address to ip address format
                        inet_address_interface = ipaddress.ip_interface(
                            inet_address)
                        inet_address_net4 = inet_address_interface.network
                        subnet_checked = is_host_in_subnet(
                            inet_address_net4, ip_without_cidr)
                        # print(subnet_checked)
                        if subnet_checked:
                            interface = line.split(" ")[4]
                            vlan = line.split(" ")[6]
                            untrust_check = "0"
                            break

                    if untrust_check == "0":
                        # zone_check = f"show configuration logical-systems {logical_system} security zones | match {interface}.{vlan} | display set "
                        for line in zone_check_result.splitlines():
                            if f"{interface}.{vlan}" in line:
                                zone_name = line.split()[6]
                                objects2create_dic.update(
                                    {ip_without_cidr: [address_name_4new, zone_name, ip_with_cidr, description, grp_name]})
                                break
                                # print(zone_name)

                    elif untrust_check == "1":
                        if gateway_check_result:
                            objects2create_dic.update(
                                {ip_without_cidr: [address_name_4new, zone_untrust, ip_with_cidr, description, grp_name]})
                # add exist object to group
            print(" Address Checking completed. Now add items to groups ...")
            print(" Adding existing object to groups ...")
            for values, _ in objects_dic.items():
                address_name = str(objects_dic[values][0])
                zone_name = str(objects_dic[values][1])
                grp_name = str(objects_dic[values][2])
                addr_group_check = f"show logical-systems {logical_system} security address-book {zone_name} address-set {grp_name} | match {address_name}"
                # print(address_check_result)
                # For junos we use ";" to determine correct input
                # if object_existence == "y":
                # print(" Object already exist!")
                addr_group_check_result = juniper_junos.send_config_set(
                    addr_group_check, read_timeout=40, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                # print(addr_group_check_result)
                # key index 0 is address name
                if f"address {address_name};" in addr_group_check_result:
                    duplicate_member += 1
                    # print(
                    #    f" address {address_name} are already in the group: {grp_name}")
                else:
                    # add address to group
                    add_to_group_command = f"set logical-systems {logical_system} security address-book {zone_name} address-set {grp_name} address {address_name}"
                    output = juniper_junos.send_config_set(
                        add_to_group_command, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    # Check last command worked or not!
                    addr_group_check_result = juniper_junos.send_config_set(
                        addr_group_check, read_timeout=40, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    if f"address {address_name};" in addr_group_check_result:
                        print(
                            f" Address {address_name} added to group: {grp_name}")
                        count += 1
                        changed = True
            # print(" Creating addresses ...")
            for values, _ in objects2create_dic.items():
                address_name_4new = str(objects2create_dic[values][0])
                zone_name_4new = str(objects2create_dic[values][1])
                item_ip = str(objects2create_dic[values][2])
                new_description = str(objects2create_dic[values][3]) or " "
                grp_name = str(objects2create_dic[values][4])
                # item_netmask = values.split("/")[1]
                # print(" Creating objects and add to group ...")
                commands = [f"set logical-systems {logical_system} security address-book {zone_name_4new} address {address_name_4new} {item_ip}",
                            f"set logical-systems {logical_system} security address-book {zone_name_4new} address {address_name_4new} description {new_description}",
                            f"set logical-systems {logical_system} security address-book {zone_name_4new} address-set {grp_name} address {address_name_4new}",
                            f"show logical-systems {logical_system} security address-book {zone_name_4new} address-set {grp_name} | match {address_name_4new}"]
                output = juniper_junos.send_config_set(
                    commands, read_timeout=40, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                # # Check last command worked or not!
                # addr_group_check = f"show logical-systems {logical_system} security address-book {zone_name_4new} address-set {grp_name} | match {address_name_4new}"
                # addr_group_check_result = juniper_junos.send_config_set(
                #     addr_group_check, read_timeout=40, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                if f"address {address_name_4new};" in output:
                    print(
                        f" Address {address_name_4new} created and added to group: {grp_name}")
                    # count += 1
                    number_of_created += 1
                    changed = True
            if changed:
                output = juniper_junos.commit(comment="Add object by script")
                if "commit complete" in output:
                    print("\n>>> commit complete")
                else:
                    print(output)
            print(
                f"                                                      {count} Object added.")
            print(
                f"                                                      {duplicate_member} objects are already in the group.")
            print(
                f"                                                      {number_of_created} objects are already in the group.")
            juniper_junos.disconnect()
        # ScreenOS ------------------------------------------------------------------
        elif host["device_type"] == "juniper_screenos":
            print(f">>> Looking in {host['host']} juniper_screenos...")
            juniper_screenos = ConnectHandler(**host)
            changed = False
            count = 0
            duplicate_member = 0
            get_interface = "get interface"
            get_interface_result = juniper_screenos.send_command(
                get_interface, expect_string=r">", read_timeout=40)
            interface_list = []
            for line in get_interface_result.splitlines():
                inet_address = re.findall(
                    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,3})', line)
                if "0.0.0.0/0" in inet_address:
                    pass
                elif inet_address:
                    interface_list.append(inet_address)
            # gateway_check = "get route 0.0.0.0/0"
            # gateway_check_result = juniper_screenos.send_command(
            #     gateway_check, expect_string=r">", read_timeout=40)
            objects_dic = {}
            objects2create_dic = {}
            for values, _ in ip_dic_validated.items():
                print("------- Address:", values)
                ip_with_cidr = values
                ip = ip_with_cidr.split("/")[0]
                ip_cidr = values.split('/')[1]
                zone_name = ""
                grp_name = ip_dic_validated[values][2]
                get_address_trust = f"get address Trust | include {ip}/"
                trust_address_check_result = juniper_screenos.send_command(
                    get_address_trust, expect_string=r">", read_timeout=40)
                get_address_untrust = f"get address Untrust | include {ip}/"
                untrust_address_check_result = juniper_screenos.send_command(
                    get_address_untrust, expect_string=r">", read_timeout=40)
                # found_in_trust = list(filter(
                #     lambda line: f" {ip_with_cidr}" in line, trust_address_check_result.splitlines()))
                # found_in_untrust = list(filter(
                #     lambda line: f" {ip_with_cidr}" in line, untrust_address_check_result.splitlines()))
                if trust_address_check_result:
                    address_name = trust_address_check_result.split(" ")[0]
                    zone_name = "Trust"
                    objects_dic.update(
                        {ip_with_cidr: [address_name, zone_name, grp_name]})
                elif untrust_address_check_result:
                    address_name = untrust_address_check_result.split(" ")[0]
                    zone_name = "Untrust"
                    objects_dic.update(
                        {ip_with_cidr: [address_name, zone_name, grp_name]})
                else:
                    ip_without_cidr = ip_with_cidr.split('/')[0]
                    convention = ip_dic_validated[values][0]
                    description = ip_dic_validated[values][1]
                    if (convention == "R_" or convention == "A_") and ip_cidr != "32":
                        address_name_4new = convention+ip_with_cidr
                    else:
                        address_name_4new = convention+ip_without_cidr
                    for interface_ip in interface_list:
                        inet_address_interface = ipaddress.ip_interface(
                            interface_ip[0])
                        inet_address_net4 = inet_address_interface.network
                        subnet_checked = is_host_in_subnet(
                            inet_address_net4, ip_with_cidr)
                        if subnet_checked:
                            zone_name = "Trust"
                            objects2create_dic.update(
                                {ip_without_cidr: [address_name_4new, zone_name, ip_with_cidr, description, grp_name]})
                        else:
                            zone_name = "Untrust"
                            objects2create_dic.update(
                                {ip_without_cidr: [address_name_4new, zone_name, ip_with_cidr, description, grp_name]})
            for values, _ in objects_dic.items():
                address_name = str(objects_dic[values][0])
                zone_name = str(objects_dic[values][1])
                grp_name = str(objects_dic[values][2])
                # check address object existence
                address_check = f'get address {zone_name} | include {address_name}'
                # then check address object existence in group
                addr_group_check = f'get group address {zone_name} {grp_name} | include {address_name}'
                address_check_result = juniper_screenos.send_command(
                    address_check, expect_string=r">")
                add_to_group_command = f'set group address {zone_name} {grp_name} add {address_name}'
                add_to_group_result = juniper_screenos.send_command(
                    add_to_group_command, expect_string=r">")
                if "Duplicate group member" in add_to_group_result:
                    duplicate_member += 1
                elif add_to_group_result:
                    print(add_to_group_result)
                else:
                    print(
                        f" Address {address_name} added to group: {grp_name}")
                    count += 1
                    changed = True
            for values, _ in objects2create_dic.items():
                address_name_4new = str(objects2create_dic[values][0])
                zone_name_4new = str(objects2create_dic[values][1])
                item_ip = str(objects2create_dic[values][2])
                new_description = str(objects2create_dic[values][3]) or " "
                grp_name = str(objects2create_dic[values][4])
                set_addr_cmd = f"set address {zone_name_4new} {address_name_4new} {item_ip}"
                set_addr_result = juniper_screenos.send_command(set_addr_cmd)
                add_grp_cmd = f"set group address {zone_name_4new} {grp_name} add {address_name_4new}"
                add_grp_result = juniper_screenos.send_command(add_grp_cmd)
                if set_addr_result:
                    print(set_addr_result)
                elif add_grp_result:
                    print(add_grp_result)
                else:
                    print(
                        f" Address {address_name_4new} created and added to group: {grp_name}")
                    count += 1
                    changed = True
            if changed:
                output = juniper_screenos.save_config()
                print(output)
            print(
                f"                                                      {count} Objects added!")
            print(
                f"                                                      {duplicate_member} objects are already in the group")
            juniper_screenos.disconnect()
    except NetmikoTimeoutException:
        print('Connection timed out')
    except NetmikoAuthenticationException:
        print('Authentication failed')


def remove_via_ssh(host, ip_dic_validated):
    """
    Remove IP addresses from groups via the API.

    This function communicates with the firewall's API to remove IP addresses from
    the specified groups. It takes a host and a dictionary of validated IP addresses
    as input.

    Args:
        host (dict): A dictionary containing host information.
        ip_dic_validated (dict): A dictionary of validated IP addresses,
                                 where keys are the IP addresses and values are
                                 relevant details.

    Returns:
        None
    """
    print("**************************** Remove via SSH ****************************")
    try:
        if host["device_type"] == "juniper_junos":
            logical_system = str(
                input(f"\n For VMOR >>> MORCO-Ls\
                \n For JMOR >>> MORCO\n Default: MORCO\n Enter logical-systems name for {host['host']} : ")
                or "MORCO")
            print(f">>> Looking in {host['host']} juniper_junos...")
            juniper_junos = ConnectHandler(**host)
            changed = False
            count = 0
            error_count = 0
            last_member_count = 0
            print(" Checking Addresses ...")
            address_check = f"show configuration logical-systems {logical_system} security address-book | display set"
            address_check_result = juniper_junos.send_command(
                address_check, expect_string=r">", read_timeout=40)
            # print(" Checking Zone names ...")
            # zone_check = f"show configuration logical-systems {logical_system} security zones | display set "
            # zone_check_result = juniper_junos.send_command(
            #     zone_check, expect_string=r">", read_timeout=40)
            objects_2remove_dic = {}
            for values, _ in ip_dic_validated.items():
                print("------- Address:", values)
                zone_name = ""
                ip_with_cidr = values
                grp_name = ip_dic_validated[values][2]
                founded_addr = list(filter(
                    lambda line, ip_addr_l=ip_with_cidr: f" {ip_addr_l}" in line, address_check_result.splitlines()))
                if founded_addr:
                    address_name = founded_addr[0].split(" ")[7]
                    # print(f" Address name: {address_name}")
                    zone_name = founded_addr[0].split(" ")[5]
                    # print(f" Zone name: {zone_name}")
                    check_addr_in_grp_cmd = f"show logical-systems {logical_system} security address-book {zone_name} address-set {grp_name} | match {address_name}"
                    # For junos we use ";" to determine correct input
                    check_addr_in_grp_result = juniper_junos.send_config_set(
                        check_addr_in_grp_cmd, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    check_addr_in_grp = list(filter(
                        lambda line, __address_name=address_name: f" {__address_name};" in line, check_addr_in_grp_result.splitlines()))
                    if check_addr_in_grp:
                        objects_2remove_dic.update(
                            {ip_with_cidr: [address_name, zone_name, grp_name]})
            for values, _ in objects_2remove_dic.items():
                address_name = str(objects_2remove_dic[values][0])
                zone_name = str(objects_2remove_dic[values][1])
                grp_name = str(objects_2remove_dic[values][2])
                # print(f" ------- Object: {address_name}")
                # for check if address is last object in group or not!
                check_last_member = f"show logical-systems {logical_system} security address-book {zone_name} address-set {grp_name}"
                # For junos we use ";" to determine correct input
                check_last_member_result = juniper_junos.send_config_set(
                    check_last_member, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                #     # function to count word 'address' in output of group member check
                #     # if count = 1 then we can't continue while group object will be deleted!
                #     # print(check_last_member_result)
                if word_count(";", check_last_member_result) > 1:
                    # delete address from group
                    del_from_group_command = f"delete logical-systems {logical_system} security address-book {zone_name} address-set {grp_name} address {address_name}"
                    # print(del_from_group_command)
                    output = juniper_junos.send_config_set(
                        del_from_group_command, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    # print(output)
                    # Check last command worked or not!
                    addr_group_check = f"show logical-systems {logical_system} security address-book {zone_name} address-set {grp_name} | match {address_name}"
                    addr_group_check_result = juniper_junos.send_config_set(
                        addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    # print(addr_group_check_result)
                    if "address " + address_name not in addr_group_check_result:
                        print(
                            f" Address {address_name} removed from group: {grp_name}")
                        count += 1
                        changed = True
                    else:
                        error_count += 1
                        print(
                            " ERROR!!! >>> while deleting object!")
                else:
                    last_member_count += 1
                    print(f" ERROR!!! >>> while deleting object! group can't be blank")
            if changed:
                output = juniper_junos.commit(
                    comment="Removed object by script")
                if "commit complete" in output:
                    print("\n>>> commit complete")
                else:
                    print(output)
            print(
                f"                                                      Removed {count} objects from group.")
            print(
                f"                                                      {last_member_count} objects are the only memeber of groups!")
            if error_count:
                print(
                    f"                                                      Unable to remove {error_count} for unknown reason!")
        # ScreenOS ------------------------------------------------------------------
        elif host["device_type"] == "juniper_screenos":
            print(f">>> Looking in {host['host']} juniper_screenos...")
            juniper_screenos = ConnectHandler(**host)
            changed = False
            count = 0
            objects_dic = {}
            for values, _ in ip_dic_validated.items():
                print("------- Address:", values)
                ip_with_cidr = values
                ip = ip_with_cidr.split("/")[0]
                zone_name = ""
                grp_name = ip_dic_validated[values][2]
                get_address_trust = f"get address Trust | include {ip}/"
                trust_address_check_result = juniper_screenos.send_command(
                    get_address_trust, expect_string=r">", read_timeout=40)
                get_address_untrust = f"get address Untrust | include {ip}/"
                untrust_address_check_result = juniper_screenos.send_command(
                    get_address_untrust, expect_string=r">", read_timeout=40)
                if trust_address_check_result:
                    address_name = trust_address_check_result.split(" ")[0]
                    zone_name = "Trust"
                    objects_dic.update(
                        {ip_with_cidr: [address_name, zone_name, grp_name]})
                elif untrust_address_check_result:
                    address_name = untrust_address_check_result.split(" ")[0]
                    zone_name = "Untrust"
                    objects_dic.update(
                        {ip_with_cidr: [address_name, zone_name, grp_name]})
                else:
                    print(" Object not found!")

            for values, _ in objects_dic.items():
                address_name = str(objects_dic[values][0])
                zone_name = str(objects_dic[values][1])
                grp_name = str(objects_dic[values][2])
                # print(" ------- Object:", address_name)
                # check address object existence
                address_check = f'get address {zone_name} | include {address_name}'
                # then check address object existence in group
                addr_group_check = f'get group address {zone_name} {grp_name} | include {address_name}'
                address_check_result = juniper_screenos.send_command(
                    address_check, expect_string=r">")
                remove_from_group_cmd = f'unset group address {zone_name} {grp_name} remove {address_name}'
                remove_from_group_result = juniper_screenos.send_command(
                    remove_from_group_cmd, expect_string=r">")
                if remove_from_group_result:
                    print(remove_from_group_result)
                else:
                    print(
                        f" Address {address_name} removed from group: {grp_name}")
                    count += 1
                    changed = True
            if changed:
                output = juniper_screenos.save_config()
                print(output)
            print(
                f"                                                      {count} Object removed!"
                "----------------------------------------")
    except NetmikoTimeoutException:
        print('Connection timed out')
    except NetmikoAuthenticationException:
        print('Authentication failed')


def add_via_api(host, ip_dic_validated):
    print("**************************** Add via API ****************************")
    print(">>> Looking in ", host["host"])
    urllib3.disable_warnings()
    count = 0

    device_ip = host["host"]
    port = host["port"]
    access_token = host["token"]
    headers = {"Authorization": "Bearer " + access_token, }
    number_of_created = 0
    duplicate_member = 0
    number_of_exist_object = 0
    gp_not_exist_count = 0
    gp_not_exist = []
    for values, _ in ip_dic_validated.items():
        print("------- Address:", values)
        ip = values.split('/')[0]
        ip_cidr = values.split('/')[1]
        convention = ip_dic_validated[values][0]
        comment = ip_dic_validated[values][1]
        grp_name = ip_dic_validated[values][2]
        url_addrgrp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/"
        response_grp_check = make_api_request(url_addrgrp, "GET", headers)
        # Check existence of Group
        if response_grp_check.status_code == 404:
            gp_not_exist_count += 1
            gp_not_exist.append(grp_name)
        elif response_grp_check.status_code == 200:
            if (convention == "R_" or convention == "A_") and ip_cidr != "32":
                address_name = convention+ip+"%2F"+ip_cidr
                # for payload
                address_name_pl = convention+values
                # print(address_name)
            else:
                address_name_pl = convention+ip
                address_name = convention+ip
            # print("------- Address:", address_name_pl)
            ip_dict = dict()
            # baraye API bejaye slash %2F bayad bzarim
            ip_dict["name"] = address_name_pl
            ip_dict["subnet"] = values
            ip_dict["comment"] = comment
            address_payload = json.dumps(ip_dict)
            # print(address_payload)
            add_member_group_dict = dict()
            add_member_group_dict["name"] = ip_dict["name"]
            add_to_group_payload = json.dumps(add_member_group_dict)
            url_address_check = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/{address_name}"
            url_address = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/"
            url_addr_in_grp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/{address_name}"
            # Check existence of address in firewall address
            # print(" Looking in firewall addresses...")
            response_addr_check = make_api_request(
                url_address_check, "GET", headers)
            if response_addr_check:
                number_of_exist_object += 1
                # rint(" Object already exist!")
            else:
                # Create Address
                # print(" Creating address:", ip_dict["name"])
                response_address = make_api_request(
                    url_address, "POST", headers, address_payload)
                if response_address.ok:
                    print(f" Address {address_name_pl} created!")
                    number_of_created += 1
                else:
                    print(" ERROR!")
            sleep(.3)
            # Check existence of address in group
            # print(" Looking in group:", grp_name, "...")
            response_addr_in_group_check = make_api_request(
                url_addr_in_grp, "GET", headers)
            # print(response_addr_in_group_check.content)
            if response_addr_in_group_check.status_code == 200:
                # print(
                #    f" also in group: {grp_name} \n Nothing changed!")
                duplicate_member += 1
            elif response_addr_in_group_check.status_code == 404:
                response_add_addr = make_api_request(
                    url_addrgrp, "POST", headers, add_to_group_payload)
                # print(response_add_addr)
                if response_add_addr.ok:
                    print(
                        f" Address {address_name_pl} added to group: {grp_name}")
                    count += 1
                else:
                    print(
                        f" ERROR! >>> adding to group {response_add_addr.status_code, response_add_addr.reason}")
            else:
                print(
                    f" ERROR! >>> something went wrong!\n{response_addr_in_group_check.status_code}")
        else:
            print(
                f" ERROR! >>> something went wrong!\n{response_grp_check.status_code}")
            break
    print(
        f"                                                      {count} Object added.")
    print(
        f"                                                      {duplicate_member} objects are already in the group.")
    print(
        f"                                                      {number_of_created} Object created.")
    if gp_not_exist_count:
        print(
            f"                                                      {gp_not_exist_count} Object can't be added, because {gp_not_exist} not found.")


def remove_via_api(host, ip_dic_validated):
    """
    Remove IP addresses from a firewall address group via API.

    This function removes IP addresses from a specified firewall address group
    using the provided API endpoints. It processes a dictionary of validated IP addresses
    and their corresponding details.

    Args:
        host (dict): A dictionary containing host information (host, port, token).
        ip_dic_validated (dict): A dictionary of validated IP addresses and their details.

    Returns:
        None

    Raises:
        SystemExit: If a request exception occurs during API communication.

    """
    print("**************************** Remove via API ****************************")
    print(">>> Looking in ", host["host"])
    urllib3.disable_warnings()
    count = 0
    device_ip = host["host"]
    port = host["port"]
    access_token = host["token"]
    headers = {"Authorization": "Bearer " + access_token, }
    for values, _ in ip_dic_validated.items():
        print("------- Address:", values)
        convention = ip_dic_validated[values][0]
        grp_name = ip_dic_validated[values][2]
        url_addrgrp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/"
        response_grp_check = make_api_request(url_addrgrp, "GET", headers)
        # Check existence of Group
        if response_grp_check.status_code == 404:
            print(f" ERROR!!! >>> Group: {grp_name} not exist!")
            break
        elif response_grp_check.status_code == 200:
            ip = values.split('/')[0]
            ip_cidr = values.split('/')[1]
            if (convention == "R_" or convention == "A_") and ip_cidr != "32":
                address_name = convention+ip+"%2F"+ip_cidr
                address_name_pl = convention+values
                # print(address_name)
            else:
                address_name = convention+ip
                address_name_pl = convention+ip

            # print("------- Object:", address_name_pl)
            ip_dict = dict()
            # baraye API bejaye slash %2F bayad bzarim
            # for payload
            ip_dict["name"] = address_name_pl
            ip_dict["subnet"] = values
            address_payload = json.dumps(ip_dict)
            # print(address_payload)
            add_member_group_dict = dict()
            add_member_group_dict["name"] = ip_dict["name"]
            remove_from_group_payload = json.dumps(add_member_group_dict)
            url_address_check = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/{address_name}"
            # url_address = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/"
            url_addr_in_grp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/{address_name}"
            # Check existence of address in firewall address
            # print(" Looking in firewall addresses...")
            response_addr_check = make_api_request(
                url_address_check, "GET", headers)
            if response_addr_check.status_code == 200:
                # Check existence of address in group
                # print(" Looking in group:", grp_name, "...")
                response_addr_in_group_check = make_api_request(
                    url_addr_in_grp, "GET", headers)
                # print(response_addr_in_group_check.content)
                if response_addr_in_group_check.status_code == 200:
                    response_remove_addr = make_api_request(
                        url_addr_in_grp, "DELETE", headers, remove_from_group_payload)
                    response_remove_addr_js = response_remove_addr.json()
                    if response_remove_addr.status_code == 200:
                        print(
                            f" Address {address_name_pl} removed from group: {grp_name}")
                        count += 1
                    elif response_remove_addr_js["error"] == -16:
                        print(
                            " ERROR!!! >>> while deleting object! group can't be blank")
                    else:
                        print(
                            f" ERROR!!! >>> {response_remove_addr.status_code}")
                elif response_addr_in_group_check.status_code == 404:
                    print(" Object not exist in group!")
                else:
                    print(
                        f" ERROR!!! >>> something went wrong!\n{response_addr_in_group_check.status_code}")
            else:
                print(
                    f" ERROR!!! >>> address not found! {response_addr_check.status_code}")
        else:
            print(
                f" ERROR!!! >>> something went wrong!\n{response_grp_check.status_code}")
            break
    print(
        f"                                                      {count} Object removed!"
        "----------------------------------------")


def add_via_sophos_api(host, ip_dic_validated):
    """
    Add IP addresses or networks to groups via the Sophos API.

    This function communicates with the Sophos API to add IP addresses or networks
    to the specified groups. It takes a host and a dictionary of validated IP addresses
    or networks as input.

    Args:
        host (dict): A dictionary containing host information.
        ip_dic_validated (dict): A dictionary of validated IP addresses or networks,
                                 where keys are the IP addresses/networks and values are
                                 relevant details.

    Returns:
        None
    """
    print("**************************** Add via Sophos API ****************************")
    print(">>> Looking in ", host["host"])
    urllib3.disable_warnings()
    count = 0
    device_ip = host["host"]
    port = host["port"]
    access_token = host["token"]
    username_token = "api-admin"
    number_of_created = 0
    number_of_exist_object = 0
    for values, _ in ip_dic_validated.items():
        print("------- Address:", values)
        ip = values.split('/')[0]
        ip_cidr = values.split('/')[1]
        subnet = ipaddress.IPv4Network(values).netmask
        operation = "add"
        convention = ip_dic_validated[values][0]
        grp_name = ip_dic_validated[values][2]
        if ip_cidr == "32":
            url_addrgrp = f'https://{device_ip}:{port}/webconsole/APIController?reqxml=<Request><Login><Username>{username_token}</Username><Password passwordform="encrypt">{access_token}</Password></Login><Set operation="{operation}"><IPHost><Name>{convention+ip}</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>{ip}</IPAddress><HostGroupList><HostGroup>{grp_name}</HostGroup></HostGroupList></IPHost></Set></Request>'
        else:
            url_addrgrp = f'https://{device_ip}:{port}/webconsole/APIController?reqxml=<Request><Login><Username>{username_token}</Username><Password passwordform="encrypt">{access_token}</Password></Login><Set operation="{operation}"><IPHost><Name>{convention+values}</Name><IPFamily>IPv4</IPFamily><HostType>Network</HostType><IPAddress>{ip}</IPAddress><Subnet>{subnet}</Subnet><HostGroupList><HostGroup>{grp_name}</HostGroup></HostGroupList></IPHost></Set></Request>'

        response_grp_check = make_api_request(url_addrgrp, "GET")

        if "Configuration applied successfully." in response_grp_check.text:
            number_of_created += 1
            print(
                f" Address {ip} added to group: {grp_name}")
            count += 1
        elif "Operation failed. Entity having same name already exists" in response_grp_check.text:
            print(" Object are already exists!")
            number_of_exist_object += 1
            operation = "update"
            if ip_cidr == "32":
                url_addrgrp = f'https://{device_ip}:{port}/webconsole/APIController?reqxml=<Request><Login><Username>{username_token}</Username><Password passwordform="encrypt">{access_token}</Password></Login><Set operation="{operation}"><IPHost><Name>{convention+ip}</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>{ip}</IPAddress><HostGroupList><HostGroup>{grp_name}</HostGroup></HostGroupList></IPHost></Set></Request>'
            else:
                url_addrgrp = f'https://{device_ip}:{port}/webconsole/APIController?reqxml=<Request><Login><Username>{username_token}</Username><Password passwordform="encrypt">{access_token}</Password></Login><Set operation="{operation}"><IPHost><Name>{convention+values}</Name><IPFamily>IPv4</IPFamily><HostType>Network</HostType><IPAddress>{ip}</IPAddress><Subnet>{subnet}</Subnet><HostGroupList><HostGroup>{grp_name}</HostGroup></HostGroupList></IPHost></Set></Request>'
            response_grp_check = make_api_request(url_addrgrp, "GET")
            if "Configuration applied successfully." in response_grp_check.text:
                print(
                    f" Address {ip} added to group: {grp_name}")
                count += 1
        elif "<Params>/IPHost/HostGroupList/HostGroup</Params>" in response_grp_check.text:
            print(f" ERROR! >>> Maybe group {grp_name} not exist!")
        else:
            print(
                f" ERROR! >>> something went wrong!\n{response_grp_check.text}")
        sleep(.3)

    print(
        f"                                                      {count} Object added.")
    print(
        f"                                                      {number_of_created} Object created.")


def forti_policy_finder(host, ip_list_validated, result_file):
    """
    Find object dependencies via Fortinet FortiGate API.

    This function takes a host configuration, a list of validated IP addresses,
    and a result file for generating the output. It analyzes network policies
    on a FortiGate device, identifying address dependencies, address groups,
    interfaces, and policies related to the given IP addresses.

    Parameters:
    host (dict): A dictionary containing host configuration details including
                 'host', 'port', and 'token' for API access.
    ip_list_validated (list): A list of validated IP addresses (with CIDR notation)
                             to analyze for dependencies.
    result_file (CSV writer): A CSV writer object to write the results.

    Returns:
    None: This function generates output in the provided result_file.

    Raises:
    SystemExit: If there's a RequestException during API calls to the FortiGate device.

    """
    print("**************************** Find policies via API ****************************")
    print(">>> Looking in ", host["host"])
    urllib3.disable_warnings()

    device_ip = host["host"]
    port = host["port"]
    access_token = host["token"]
    headers = {"Authorization": "Bearer " + access_token, }
    # Write header for device in csv file
    result_file.writerow([host["host"]])
    # Get all address
    url_all_addr = f'https://{device_ip}:{port}/api/v2/cmdb/firewall/address/?format=name|subnet|type&filter=type==ipmask'
    response_all_addr_check = make_api_request(
        url_all_addr, "GET", headers).json()["results"]
    # get interfaces to find vlan of ip address
    url_all_interfaces = f'https://{device_ip}:{port}/api/v2/cmdb/system/interface/?format=ip|name'
    response_interface_check = make_api_request(
        url_all_interfaces, "GET", headers).json()["results"]
    all_interfaces = list(
        map(lambda x: {**x, "ip": x["ip"].replace(' ', '/')}, response_interface_check))
    # Find zones
    url_all_zones = f'https://{device_ip}:{port}/api/v2/cmdb/system/zone/?format=name|interface'
    response_zone_check = make_api_request(
        url_all_zones, "GET", headers).json()["results"]
    # Find subnets and replace space with slash in subnet value for use in subnet_of() function
    all_subnet = list(map(lambda x: {
        **x, "subnet": x["subnet"].replace(' ', '/')}, response_all_addr_check))
    # Get all groups
    url_addrgrp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/?format=name|member"
    response_grp_check = make_api_request(
        url_addrgrp, "GET", headers).json()["results"]
    # Get all policies
    url_all_policy = f'https://{device_ip}:{port}/api/v2/cmdb/firewall/policy/'
    result_url_all_policy = make_api_request(
        url_all_policy, "GET", headers).json()["results"]
    for ip_with_cidr in ip_list_validated:
        print("------- Address:", ip_with_cidr)
        result_file.writerow(["------- Address:", ip_with_cidr])
        ip_without_cidr = ip_with_cidr.split('/')[0]
        founded_grp_list = []
        subnet_check = list(
            filter(lambda x, ip_addr_l=ip_with_cidr: is_host_in_subnet(x["subnet"], ip_addr_l), all_subnet))
        filtered_addresses = list(filter(lambda x, ip_addr_l=ip_without_cidr: x["subnet"].split()[
            0] == ip_addr_l, response_all_addr_check))
        if filtered_addresses:
            address_name = filtered_addresses[0]["name"]
        else:
            address_name = None
        # Count all groups and check address in every group
        for res_group in response_grp_check:
            for member in res_group["member"]:
                if res_group["name"] not in founded_grp_list and member["name"] == address_name:
                    founded_grp_list.append(res_group["name"])
                # founded_grp_list.append(subnet['name'] for subnet in subnet_check if subnet['name'] == member["name"])
                for subnet in subnet_check:
                    if res_group["name"] not in founded_grp_list and subnet['name'] == member["name"]:
                        founded_grp_list.append(res_group["name"])
        # Add matched subnet name with the ip address to the list
        for subnet in subnet_check:
            founded_grp_list.append(subnet['name'])
        # find vlan of address
        interface_check = list(
            map(lambda x, ip_addr_l=ip_with_cidr: [x["name"], x["ip"]] if
                is_host_in_subnet(x["ip"], ip_addr_l) else False, all_interfaces))
        filtered_interfaces_list = list(filter(None, interface_check))
        filtered_zone = "unknown-zone"
        filtered_interface = "unknown-int"
        if filtered_interfaces_list:
            filtered_interface = filtered_interfaces_list[0][0]
            zones_with_interface = list(
                map(
                    lambda int_name: int_name["name"],
                    filter(
                        lambda int_name: any(
                            filtered_interface in zone["interface-name"]
                            for zone in int_name["interface"]
                        ),
                        response_zone_check,
                    ),
                )
            )
            if zones_with_interface:
                filtered_zone = zones_with_interface[0]
        # print(founded_grp_list)
        # Check source and destination address and group in policy
        for pid in result_url_all_policy:
            pid_policyid = pid["policyid"]
            pid_srcaddr = list(map(lambda x: x["name"], pid["srcaddr"]))
            pid_dstaddr = list(map(lambda x: x["name"], pid["dstaddr"]))
            pid_schedule = pid["schedule"]
            pid_action = pid["action"]
            pid_status = pid["status"]
            pid_services = list(map(lambda x: x['name'], pid["service"]))
            pid_srcint = pid["srcintf"][0]["name"]
            pid_dstint = pid["dstintf"][0]["name"]
            if pid_status == "enable":
                for grp in founded_grp_list:
                    srcaddr_check = grp in pid_srcaddr
                    dstaddr_check = grp in pid_dstaddr
                    srcint_check = (
                        filtered_zone or filtered_interface) in pid_srcint
                    if grp == "all" and pid_action == "deny":
                        pass
                    elif srcaddr_check and srcint_check:
                        result_file.writerow([
                            pid_policyid, ip_without_cidr, pid_dstaddr, pid_srcint,
                            pid_dstint, pid_services, pid_schedule, pid_action
                        ])
                    elif dstaddr_check:
                        result_file.writerow([
                            pid_policyid, pid_srcaddr, ip_without_cidr, pid_srcint,
                            pid_dstint, pid_services, pid_schedule, pid_action
                        ])
    print(
        f"\n    Finished! you can see result in:\
                {os.path.join(path, 'Dependencies_Result.csv')}")


if __name__ == "__main__":
    EXIT_CODE = "n"
    while EXIT_CODE != "y":
        try:
            parsed_yaml = read_yaml()
            # Action map for each device type and user choice
            action_map = {
                "juniper_screenos": {
                    "1": add_via_ssh,
                    "2": remove_via_ssh,
                },
                "juniper_junos": {
                    "1": add_via_ssh,
                    "2": remove_via_ssh,
                },
                "fortinet": {
                    "1": add_via_api,
                    "2": remove_via_api,
                    "3": forti_policy_finder,
                },
                "sophos": {
                    "1": add_via_sophos_api,
                },
            }
            print("\n Input file: IP_LIST.csv\n")
            user_choice = input(
                "1: Add IP to group\n"
                "2: Remove IP from group\n"
                "3: Find object related policies\n"
                "Choose an option: (1 | 2 | 3) "
            )
            with open("IP_LIST.csv", encoding="utf-8") as file,\
                    open("Dependencies_Result.csv", "w",
                         newline='', encoding="utf-8") as csv_result:
                result_file = csv.writer(csv_result)
                result_file.writerow(
                    ["policyid", "srcaddr", "dstaddr", "srcintf", "dstintf", "services", "schedule", "action"])
                not_assigned_group = []
                csvreader = csv.reader(file)
                ip_dic_validated = {}
                ip_list_validated = []
                for IP_line in csvreader:
                    # remove \n from line
                    # print(IP_line[0])
                    # print(IP_line[1])
                    # print(IP_line[2])
                    ip_with_cidr = IP_line[0]
                    if "/" not in ip_with_cidr:
                        ip_with_cidr = ip_with_cidr+"/32"
                    convention = IP_line[1]
                    description = IP_line[2] or " "
                    if IP_line[3] and user_choice != "3":
                        grp_name = IP_line[3]
                        ip_validated = valiadate_ip(ip_with_cidr)
                        if ip_validated:
                            # for duplicate items
                            # if ip_with_cidr not in ip_dic_validated.items():
                            ip_dic_validated.update(
                                {ip_with_cidr: [convention, description, grp_name]})
                    elif user_choice == "3":
                        ip_validated = valiadate_ip(ip_with_cidr)
                        if ip_validated:
                            ip_list_validated.append(ip_with_cidr)
                    else:
                        print(
                            f" Group not assigned for {ip_with_cidr} in IP_LIST.csv")
                        not_assigned_group.append(ip_with_cidr)
                print(
                    "----------------------------------"
                    "\nIP validation has finished process!\n"
                    "----------------------------------"
                )

                if not_assigned_group and user_choice != "3":
                    print(" These IP addresses has no group name assigned!")
                    for grp_name in not_assigned_group:
                        print(grp_name)

                for host in parsed_yaml["hosts"]:
                    device_type = host["device_type"]
                    if device_type in action_map:
                        if user_choice in action_map[device_type]:
                            action_function = action_map[device_type][user_choice]
                            if user_choice == "3" and device_type == "fortinet":
                                action_function(host, ip_list_validated, result_file)
                            else:
                                action_function(host, ip_dic_validated)
                        else:
                            print(f"Invalid choice for device type: {device_type}")
                    else:
                        print(f"Unsupported device type: {device_type}")

        except FileNotFoundError as file_error:
            print("File not found error:", file_error)
        except csv.Error as csv_error:
            print("CSV error:", csv_error)
        except KeyError as key_error:
            print("Key error:", key_error)
        except Exception as e:
            print("An error occurred:", e)

        EXIT_CODE = str(input("\n Finished! Exit?! (y/n) ")
                        or "y").strip().lower()
        if EXIT_CODE in ("y", "yes"):
            os.sys.exit(0)

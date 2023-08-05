import yaml
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from time import sleep
import ipaddress
import requests
import json
import re
import csv
import os
# import logging
# logging.basicConfig(filename='netmiko_global.log', level=logging.DEBUG)
# logger = logging.getLogger("netmiko")
# With the __file__ and os.path functions, you can change the current directory to the directory containing the running script file
os.chdir(os.path.dirname(os.path.abspath(__file__)))
path = os.getcwd()
print(path)


def read_yaml(path="inventory.yml"):
    with open(path) as f:
        yaml_content = yaml.safe_load(f.read())
        # print(yaml_content)
    return yaml_content


def word_count(str, data):
    counts = 0
    words = data.split()
    for word in words:
        if str in word:
            counts += 1
        # print(counts,word)
    return counts


def is_host_in_subnet(subnet, ip):
    for x in subnet.hosts():
        if ip == str(x):
            # print(subnet)
            # print(ip)
            return str(subnet)


def valiadate_ip(ip):
    try:
        print(f"-------------------------\nChecking {ip} ...")
        if ip == "169.254.0.0" or ip == "0.0.0.0/0":
            raise ValueError
        ip_interface = ipaddress.ip_interface(ip)
        # ip_mask = ip_interface.with_netmask.split('/')[1]
        # pref_len = ip_interface.with_prefixlen.split('/')[1]
        if ip_interface:
            print(" IP:", ip, "is valid.")
            return str(ip_interface)

    except ValueError:
        print(" IP address is not valid!")


def Config_via_SSH(host, ip_dic_validated):
    print("**************************** Add via SSH ****************************")
    try:
        if host["device_type"] == "juniper_junos":
            logical_system = str(
                input(f"\n Enter logical-systems name for {host['host']} : ")or "BMC")
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
                subnet4check_v4 = ipaddress.ip_interface(subnet4check)
                subnet4check_net = subnet4check_v4.network
                subnet_checked = is_host_in_subnet(
                    subnet4check_net, gateway_ip)
                if subnet_checked:
                    interface_of_gw = line.split(" ")[4]
                    vlan_of_gw = line.split(" ")[6]
                    for line in zone_check_result.splitlines():
                        if f"{interface_of_gw}.{vlan_of_gw}" in line:
                            zone_untrust = line.split()[6]
                            print(f" Zone Untrust is: {zone_untrust}")
                            break
            for item in ip_dic_validated:
                print("------- Address:", item)
                grp_name = ip_dic_validated[item][2]
                zone_name = ""
                ip_with_mask = item
                founded_addr = list(filter(
                    lambda line: f" {ip_with_mask}" in line, address_check_result.splitlines()))
                if founded_addr:
                    address_name = founded_addr[0].split(" ")[7]
                    zone_name = founded_addr[0].split(" ")[5]
                    objects_dic.update(
                        {ip_with_mask: [address_name, zone_name, grp_name]})
                else:
                    untrust_check = "1"
                    ip_without_cidr = ip_with_mask.split('/')[0]
                    convention = ip_dic_validated[item][0]
                    description = ip_dic_validated[item][1]
                    if convention == "R_" or convention == "A_":
                        address_name_4new = convention+ip_with_mask
                    else:
                        address_name_4new = convention+ip_without_cidr
                    interface = ""
                    vlan = ""
                    # subnet_checker(subnet_check_result,ip_without_cidr)
                    # founded_addr = list(filter(lambda line: f" {ip_with_mask}" in line, subnet_check_result.splitlines()))
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
                                    {ip_without_cidr: [address_name_4new, zone_name, ip_with_mask, description, grp_name]})
                                break
                                # print(zone_name)

                    elif untrust_check == "1":
                        if gateway_check_result:
                            objects2create_dic.update(
                                {ip_without_cidr: [address_name_4new, zone_untrust, ip_with_mask, description, grp_name]})
                # add exist object to group
            print(" Address Checking completed. Now add items to groups ...")
            print(" Adding existing object to groups ...")
            for item in objects_dic:
                address_name = str(objects_dic[item][0])
                zone_name = str(objects_dic[item][1])
                grp_name = str(objects_dic[item][2])
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
                    #    f" address {address_name} already exist in group: {grp_name}")
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
            for item in objects2create_dic:
                address_name_4new = str(objects2create_dic[item][0])
                zone_name_4new = str(objects2create_dic[item][1])
                item_ip = str(objects2create_dic[item][2])
                new_description = str(objects2create_dic[item][3]) or " "
                grp_name = str(objects2create_dic[item][4])
                # item_netmask = item.split("/")[1]
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
                f"                                                      {duplicate_member} Object was already exist in group.")
            print(
                f"                                                      {number_of_created} Object created and added to group.")
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
            for item in ip_dic_validated:
                print("------- Address:", item)
                ip_with_mask = item
                ip = ip_with_mask.split("/")[0]
                zone_name = ""
                grp_name = ip_dic_validated[item][2]
                get_address_trust = f"get address Trust | include {ip}/"
                trust_address_check_result = juniper_screenos.send_command(
                    get_address_trust, expect_string=r">", read_timeout=40)
                get_address_untrust = f"get address Untrust | include {ip}/"
                untrust_address_check_result = juniper_screenos.send_command(
                    get_address_untrust, expect_string=r">", read_timeout=40)
                # found_in_trust = list(filter(
                #     lambda line: f" {ip_with_mask}" in line, trust_address_check_result.splitlines()))
                # found_in_untrust = list(filter(
                #     lambda line: f" {ip_with_mask}" in line, untrust_address_check_result.splitlines()))
                if trust_address_check_result:
                    address_name = trust_address_check_result.split(" ")[0]
                    zone_name = "Trust"
                    objects_dic.update(
                        {ip_with_mask: [address_name, zone_name, grp_name]})
                elif untrust_address_check_result:
                    address_name = untrust_address_check_result.split(" ")[0]
                    zone_name = "Untrust"
                    objects_dic.update(
                        {ip_with_mask: [address_name, zone_name, grp_name]})
                else:
                    ip_without_cidr = ip_with_mask.split('/')[0]
                    convention = ip_dic_validated[item][0]
                    description = ip_dic_validated[item][1]
                    if convention == "R_" or convention == "A_":
                        address_name_4new = convention+ip_with_mask
                    else:
                        address_name_4new = convention+ip_without_cidr
                    for interface_ip in interface_list:
                        inet_address_interface = ipaddress.ip_interface(
                            interface_ip[0])
                        inet_address_net4 = inet_address_interface.network
                        subnet_checked = is_host_in_subnet(
                            inet_address_net4, ip_with_mask)
                        if subnet_checked:
                            zone_name = "Trust"
                            objects2create_dic.update(
                                {ip_without_cidr: [address_name_4new, zone_name, ip_with_mask, description, grp_name]})
                        else:
                            zone_name = "Untrust"
                            objects2create_dic.update(
                                {ip_without_cidr: [address_name_4new, zone_name, ip_with_mask, description, grp_name]})
            for item in objects_dic:
                address_name = str(objects_dic[item][0])
                zone_name = str(objects_dic[item][1])
                grp_name = str(objects_dic[item][2])
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
            for item in objects2create_dic:
                address_name_4new = str(objects2create_dic[item][0])
                zone_name_4new = str(objects2create_dic[item][1])
                item_ip = str(objects2create_dic[item][2])
                new_description = str(objects2create_dic[item][3]) or " "
                grp_name = str(objects2create_dic[item][4])
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
                f"                                                      {duplicate_member} Objects were already exist in group!")
            juniper_screenos.disconnect()
    except NetmikoTimeoutException:
        print('Connection timed out')
    except NetmikoAuthenticationException:
        print('Authentication failed')


def Remove_via_SSH(host, ip_dic_validated):
    print("**************************** Remove via SSH ****************************")
    try:
        if host["device_type"] == "juniper_junos":
            logical_system = str(
                input(f"\n Enter logical-systems name for {host['host']} : ")or "BMC")
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
            for item in ip_dic_validated:
                print("------- Address:", item)
                zone_name = ""
                ip_with_mask = item
                grp_name = ip_dic_validated[item][2]
                founded_addr = list(filter(
                    lambda line: f" {ip_with_mask}" in line, address_check_result.splitlines()))
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
                        lambda line: f" {address_name};" in line, check_addr_in_grp_result.splitlines()))
                    if check_addr_in_grp:
                        objects_2remove_dic.update(
                            {ip_with_mask: [address_name, zone_name, grp_name]})
            for item in objects_2remove_dic:
                address_name = str(objects_2remove_dic[item][0])
                zone_name = str(objects_2remove_dic[item][1])
                grp_name = str(objects_2remove_dic[item][2])
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
            for item in ip_dic_validated:
                print("------- Address:", item)
                ip_with_mask = item
                ip = ip_with_mask.split("/")[0]
                zone_name = ""
                grp_name = ip_dic_validated[item][2]
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
                        {ip_with_mask: [address_name, zone_name, grp_name]})
                elif untrust_address_check_result:
                    address_name = untrust_address_check_result.split(" ")[0]
                    zone_name = "Untrust"
                    objects_dic.update(
                        {ip_with_mask: [address_name, zone_name, grp_name]})
                else:
                    print(" Object not found!")

            for item in objects_dic:
                address_name = str(objects_dic[item][0])
                zone_name = str(objects_dic[item][1])
                grp_name = str(objects_dic[item][2])
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
                f"                                                      {count} Object removed!")
    except NetmikoTimeoutException:
        print('Connection timed out')
    except NetmikoAuthenticationException:
        print('Authentication failed')


def Config_via_API(host, ip_dic_validated):
    print("**************************** Add via API ****************************")
    print(">>> Looking in ", host["host"])
    requests.packages.urllib3.disable_warnings()
    count = 0
    try:
        device_ip = host["host"]
        port = host["port"]
        access_token = host["token"]
        headers = {"Authorization": "Bearer " + access_token, }
        number_of_created = 0
        duplicate_member = 0
        number_of_exist_object = 0
        gp_not_exist_count = 0
        gp_not_exist = []
        for item in ip_dic_validated:
            print("------- Address:", item)
            ip = item.split('/')[0]
            ip_mask = item.split('/')[1]
            convention = ip_dic_validated[item][0]
            comment = ip_dic_validated[item][1]
            grp_name = ip_dic_validated[item][2]
            url_addrgrp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/"
            response_grp_check = requests.request(
                "GET", url_addrgrp, verify=False, headers=headers)
            # Check existence of Group
            if response_grp_check.status_code == 404:
                gp_not_exist_count += 1
                gp_not_exist.append(grp_name)
            elif response_grp_check.status_code == 200:
                if convention == "R_" or convention == "A_":
                    address_name = convention+ip+"%2F"+ip_mask
                    # for payload
                    address_name_pl = convention+item
                    # print(address_name)
                else:
                    address_name_pl = convention+ip
                    address_name = convention+ip
                # print("------- Address:", address_name_pl)
                ip_dict = dict()
                # baraye API bejaye slash %2F bayad bzarim
                ip_dict["name"] = address_name_pl
                ip_dict["subnet"] = item
                ip_dict["comment"] = comment
                address_payload = json.dumps(ip_dict)
                # print(address_payload)
                add_member_group_dict = dict()
                add_member_group_dict["name"] = ip_dict["name"]
                group_payload = json.dumps(add_member_group_dict)
                url_address_check = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/{address_name}"
                url_address = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/"
                url_addr_in_grp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/{address_name}"
                # Check existence of address in firewall address
                # print(" Looking in firewall addresses...")
                response_addr_check = requests.request(
                    "GET", url_address_check, verify=False, headers=headers, data=address_payload)
                if response_addr_check:
                    number_of_exist_object += 1
                    # rint(" Object already exist!")
                else:
                    # Create Address
                    # print(" Creating address:", ip_dict["name"])
                    response_address = requests.request(
                        "POST", url_address, verify=False, headers=headers, data=address_payload)
                    if response_address.ok:
                        print(f" Address {address_name_pl} created!")
                        number_of_created += 1
                    else:
                        print(" ERROR!")
                sleep(.3)
                # Check existence of address in group
                # print(" Looking in group:", grp_name, "...")
                response_addr_in_group_check = requests.request(
                    "GET", url_addr_in_grp, verify=False, headers=headers)
                # print(response_addr_in_group_check.content)
                if response_addr_in_group_check.status_code == 200:
                    # print(
                    #    f" also in group: {grp_name} \n Nothing changed!")
                    duplicate_member += 1
                elif response_addr_in_group_check.status_code == 404:
                    response_addrgrp = requests.request(
                        "POST", url_addrgrp, verify=False, headers=headers, data=group_payload)
                    # print(response_addrgrp)
                    if response_addrgrp.ok:
                        print(
                            f" Address {address_name_pl} added to group: {grp_name}")
                        count += 1
                    else:
                        print(" ERROR! >>> adding to group")
                else:
                    print(
                        f" ERROR! >>> Something went wrong!\n{response_addr_in_group_check.status_code}")
            else:
                print(
                    f" ERROR! >>> Something went wrong!\n{response_grp_check.status_code}")
                break
        print(
            f"                                                      {count} Object added.")
        print(
            f"                                                      {duplicate_member} Object was already exist in group.")
        print(
            f"                                                      {number_of_created} Object created.")
        if gp_not_exist_count:
            print(
                f"                                                      {gp_not_exist_count} Object can't be added, because {gp_not_exist} not found.")
    except requests.exceptions.RequestException as httpGetError:
        raise SystemExit(httpGetError)


def Remove_via_API(host, ip_dic_validated):
    print("**************************** Remove via API ****************************")
    print(">>> Looking in ", host["host"])
    requests.packages.urllib3.disable_warnings()
    count = 0
    try:
        device_ip = host["host"]
        port = host["port"]
        access_token = host["token"]
        headers = {"Authorization": "Bearer " + access_token, }
        for item in ip_dic_validated:
            print("------- Address:", item)
            convention = ip_dic_validated[item][0]
            grp_name = ip_dic_validated[item][2]
            url_addrgrp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/"
            response_grp_check = requests.request(
                "GET", url_addrgrp, verify=False, headers=headers)
            # Check existence of Group
            if response_grp_check.status_code == 404:
                print(f" ERROR!!! >>> Group: {grp_name} not exist!")
                break
            elif response_grp_check.status_code == 200:
                ip = item.split('/')[0]
                ip_mask = item.split('/')[1]
                if convention == "R_" or convention == "A_":
                    address_name = convention+ip+"%2F"+ip_mask
                    address_name_pl = convention+item
                    # print(address_name)
                else:
                    address_name = convention+ip
                    address_name_pl = convention+ip

                # print("------- Object:", address_name_pl)
                ip_dict = dict()
                # baraye API bejaye slash %2F bayad bzarim
                # for payload
                ip_dict["name"] = address_name_pl
                ip_dict["subnet"] = item
                address_payload = json.dumps(ip_dict)
                # print(address_payload)
                add_member_group_dict = dict()
                add_member_group_dict["name"] = ip_dict["name"]
                group_payload = json.dumps(add_member_group_dict)
                url_address_check = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/{address_name}"
                # url_address = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/"
                url_addr_in_grp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/{address_name}"
                # Check existence of address in firewall address
                # print(" Looking in firewall addresses...")
                response_addr_check = requests.request(
                    "GET", url_address_check, verify=False, headers=headers, data=address_payload)
                if response_addr_check.status_code == 200:
                    # Check existence of address in group
                    # print(" Looking in group:", grp_name, "...")
                    response_addr_in_group_check = requests.request(
                        "GET", url_addr_in_grp, verify=False, headers=headers)
                    # print(response_addr_in_group_check.content)
                    if response_addr_in_group_check.status_code == 200:
                        response_addrgrp = requests.request(
                            "DELETE", url_addr_in_grp, verify=False, headers=headers, data=group_payload)
                        response_addrgrp_js = response_addrgrp.json()
                        if response_addrgrp.status_code == 200:
                            print(
                                f" Address {address_name_pl} removed from group: {grp_name}")
                            count += 1
                        elif response_addrgrp_js["error"] == -16:
                            print(
                                " ERROR!!! >>> while deleting object! group can't be blank")
                        else:
                            print(
                                f" ERROR!!! >>> {response_addrgrp.status_code}")
                    elif response_addr_in_group_check.status_code == 404:
                        print(" Object not exist in group!")
                    else:
                        print(
                            f" ERROR!!! >>> Something went wrong!\n{response_addr_in_group_check.status_code}")
                else:
                    print(f" ERROR!!! >>> {response_addr_check.status_code}")
            else:
                print(
                    f" ERROR!!! >>> Something went wrong!\n{response_grp_check.status_code}")
                break
        print(
            f"                                                      {count} Object removed!")
    except requests.exceptions.RequestException as httpGetError:
        raise SystemExit(httpGetError)


def Sophos_API(host, ip_dic_validated):
    print("**************************** Add via Sophos API ****************************")
    print(">>> Looking in ", host["host"])
    requests.packages.urllib3.disable_warnings()
    count = 0
    try:
        device_ip = host["host"]
        port = host["port"]
        access_token = host["token"]
        username_token = "api-admin"
        number_of_created = 0
        number_of_exist_object = 0
        for item in ip_dic_validated:
            print("------- Address:", item)
            ip = item.split('/')[0]
            ip_mask = item.split('/')[1]
            subnet = ipaddress.IPv4Network(item).netmask
            operation = "add"
            convention = ip_dic_validated[item][0]
            grp_name = ip_dic_validated[item][2]
            if ip_mask == "32":
                url_addrgrp = f'https://{device_ip}:{port}/webconsole/APIController?reqxml=<Request><Login><Username>{username_token}</Username><Password passwordform="encrypt">{access_token}</Password></Login><Set operation="{operation}"><IPHost><Name>{convention+ip}</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>{ip}</IPAddress><HostGroupList><HostGroup>{grp_name}</HostGroup></HostGroupList></IPHost></Set></Request>'
            else:
                url_addrgrp = f'https://{device_ip}:{port}/webconsole/APIController?reqxml=<Request><Login><Username>{username_token}</Username><Password passwordform="encrypt">{access_token}</Password></Login><Set operation="{operation}"><IPHost><Name>{convention+item}</Name><IPFamily>IPv4</IPFamily><HostType>Network</HostType><IPAddress>{ip}</IPAddress><Subnet>{subnet}</Subnet><HostGroupList><HostGroup>{grp_name}</HostGroup></HostGroupList></IPHost></Set></Request>'

            response_grp_check = requests.request(
                "GET", url_addrgrp, verify=False)

            if "Configuration applied successfully." in response_grp_check.text:
                number_of_created += 1
                print(
                    f" Address {ip} added to group: {grp_name}")
                count += 1
            elif "Operation failed. Entity having same name already exists" in response_grp_check.text:
                print(" Operation failed. Entity having same name already exists!")
                number_of_exist_object += 1
                operation = "update"
                if ip_mask == "32":
                    url_addrgrp = f'https://{device_ip}:{port}/webconsole/APIController?reqxml=<Request><Login><Username>{username_token}</Username><Password passwordform="encrypt">{access_token}</Password></Login><Set operation="{operation}"><IPHost><Name>{convention+ip}</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>{ip}</IPAddress><HostGroupList><HostGroup>{grp_name}</HostGroup></HostGroupList></IPHost></Set></Request>'
                else:
                    url_addrgrp = f'https://{device_ip}:{port}/webconsole/APIController?reqxml=<Request><Login><Username>{username_token}</Username><Password passwordform="encrypt">{access_token}</Password></Login><Set operation="{operation}"><IPHost><Name>{convention+item}</Name><IPFamily>IPv4</IPFamily><HostType>Network</HostType><IPAddress>{ip}</IPAddress><Subnet>{subnet}</Subnet><HostGroupList><HostGroup>{grp_name}</HostGroup></HostGroupList></IPHost></Set></Request>'
                response_grp_check = requests.request(
                    "GET", url_addrgrp, verify=False)
                if "Configuration applied successfully." in response_grp_check.text:
                    print(
                        f" Address {ip} added to group: {grp_name}")
                    count += 1
            elif "<Params>/IPHost/HostGroupList/HostGroup</Params>" in response_grp_check.text:
                print(f" ERROR! >>> Maybe group {grp_name} not exist!")
            else:
                print(
                    f" ERROR! >>> Something went wrong!\n{response_grp_check.text}")
            sleep(.3)

        print(
            f"                                                      {count} Object added.")
        print(
            f"                                                      {number_of_created} Object created.")
    except requests.exceptions.RequestException as httpGetError:
        raise SystemExit(httpGetError)


if __name__ == "__main__":
    EXIT = "n"
    while EXIT != "y":
        parsed_yaml = read_yaml()
        user_choice = input(
            "\n 1: Add IP to group\n 2: Remove IP from group\nChoose an option:(1|2)")
        print("\n Input file: IP_LIST.csv\n")
        if not re.match("[1,2]", user_choice):
            print("ERROR!!! Only 1 or 2 allowed!")
        else:
            # grp_name = str(input("\n |Default: Grp-Blocked-Addresses|\n Enter Group name: ")
            #                or "testapi")  # "Grp-Blocked-Addresses")  # "testapi"
            with open("IP_LIST.csv") as file:
                not_assigned_group = []
                csvreader = csv.reader(file)
                ip_dic_validated = {}
                for IP_line in csvreader:
                    # remove \n from line
                    # print(IP_line[0])
                    # print(IP_line[1])
                    # print(IP_line[2])
                    ip_with_mask = IP_line[0]
                    if "/" not in ip_with_mask:
                        ip_with_mask = ip_with_mask+"/32"
                    convention = IP_line[1]
                    description = IP_line[2] or " "
                    if IP_line[3]:
                        grp_name = IP_line[3]
                        ip_validated = valiadate_ip(ip_with_mask)
                        if ip_validated:
                            # for duplicate items
                            # if ip_with_mask not in ip_dic_validated:
                            ip_dic_validated.update(
                                {ip_with_mask: [convention, description, grp_name]})
                    else:
                        print(
                            f" Group not assigned for {ip_with_mask} in IP_LIST.csv")
                        not_assigned_group.append(ip_with_mask)
                print(
                    "----------------------------------\nIP validation has finished process!\n----------------------------------")
                for host in parsed_yaml["hosts"]:
                    if "juniper" in host["device_type"]:
                        ssh_host_dict = {}
                        # ssh_host_dict.update(login_credentials)
                        ssh_host_dict.update(host)
                        if user_choice == "1":
                            Config_via_SSH(
                                ssh_host_dict, ip_dic_validated)
                        elif user_choice == "2":
                            Remove_via_SSH(ssh_host_dict, ip_dic_validated)
                    elif host["device_type"] == "fortinet":
                        if user_choice == "1":
                            Config_via_API(host, ip_dic_validated)
                        elif user_choice == "2":
                            Remove_via_API(host, ip_dic_validated)
                    elif host["device_type"] == "sophos":
                        if user_choice == "1":
                            Sophos_API(host, ip_dic_validated)

                if not_assigned_group:
                    print(" These IP addresses has no group name assigned!")
                    for item in not_assigned_group:
                        print(item)

        EXIT = str(input("\n Finished! Exit?! (y/n) ") or "y")

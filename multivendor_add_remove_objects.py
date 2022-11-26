import yaml
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from time import sleep
import ipaddress
import requests
import json
import re
import sys
# import logging

# logging.basicConfig(filename='netmiko_global.log', level=logging.DEBUG)
# logger = logging.getLogger("netmiko")


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


def remove_slash(ip):
    def second_group(m):
        return m.group(1)
    ip_without_slash = re.sub("(.*)(.{3}$)", second_group, ip)
    return ip_without_slash


def valiadate_ip(ip):
    try:
        print(f"-------------------------\nChecking {ip} ...")
        ip_interface = ipaddress.ip_interface(ip)
        #ip_mask = ip_interface.with_netmask.split('/')[1]
        #pref_len = ip_interface.with_prefixlen.split('/')[1]
        if ip_interface:
            print(" IP:", ip, "is valid.")
            return str(ip_interface)

    except ValueError:
        print(" IP address is not valid!")


def Config_via_SSH(host, ip_list_validated, grp_name, logical_system, zone_name):
    print("**************************** Add via SSH ****************************")
    try:
        if host["device_type"] == "juniper_junos":
            print(f">>> Looking in {host['host']} juniper_junos...")
            juniper_junos = ConnectHandler(**host)
            count = 0
            changed = False
            # Check existense of security zone
            zone_check = f"show configuration logical-systems {logical_system} security zones | match {zone_name}"
            zone_check_result = juniper_junos.send_command(
                zone_check, expect_string=r">", read_timeout=20)
            # print(zone_check_result)
            while f"security-zone {zone_name} " not in zone_check_result:
                if zone_name in zone_check_result:
                    if word_count(zone_name, zone_check_result) > 1:
                        print(zone_check_result)
                        zone_name = str(
                            input(" Multiple zone founded!\n Enter correct zone: "))
                    else:
                        print(zone_check_result)
                        zone_name = str(zone_check_result.split()[1])
                else:
                    print(zone_check_result)
                    print(f" Zone name {zone_name} not found!")
                    zone_name = str(input(" Enter correct zone: "))
                zone_check_result = juniper_junos.send_command(
                    f"show configuration logical-systems {logical_system} security zones | match {zone_name}", expect_string=r">", read_timeout=20)
                print(f" Zone name: {zone_name}")
            # Check if group name is correct or exist
            group_check = f"show configuration logical-systems {logical_system} security address-book {zone_name} | match {grp_name}"
            group_check_result = juniper_junos.send_command(
                group_check, expect_string=r">", read_timeout=20)
            create_grp = "n"
            # print(group_check_result)
            if f"address-set {grp_name}" not in group_check_result:
                print(f" ERROR! >>> Group: {grp_name} not exist!")
                create_grp_c = input(" \n Do you want to create it? (y/n) ")
                # check input
                if re.match("[Y,y,n,N]", create_grp):
                    create_grp = create_grp_c
                else:
                    print(" Wrong answer!")
            if f"address-set {grp_name}" in group_check_result or create_grp == "y":
                for ip_with_mask in ip_list_validated:
                    #ip = remove_slash(ip_with_mask)
                    address_name = convention+ip_with_mask
                    print(f" ------- Object: {address_name}")
                    # then check address object existence
                    address_check = f"show logical-systems {logical_system} security address-book {zone_name} address {address_name}"
                    # then check address object existence in group
                    addr_group_check = f"show logical-systems {logical_system} security address-book {zone_name} address-set {grp_name} | match {address_name}"
                    address_check_result = juniper_junos.send_config_set(
                        address_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    # print(address_check_result)
                    # For junos we use ";" to determine correct input
                    if f"{ip_with_mask};" in address_check_result:
                        print(" Object already exist!")
                        addr_group_check_result = juniper_junos.send_config_set(
                            addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                        # print(addr_group_check_result)
                        if "address " + address_name in addr_group_check_result:
                            print(
                                f" also in group: {grp_name}")
                        else:
                            # add address to group
                            add_to_group_command = f"set logical-systems {logical_system} security address-book {zone_name} address-set {grp_name} address {address_name}"
                            output = juniper_junos.send_config_set(
                                add_to_group_command, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                            # Check last command worked or not!
                            addr_group_check_result = juniper_junos.send_config_set(
                                addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                            if address_name in addr_group_check_result:
                                print(f" Object added to group: {grp_name}")
                                count += 1
                                changed = True
                    else:
                        commands = [f"set logical-systems {logical_system} security address-book {zone_name} address {address_name} {ip_with_mask}",
                                    f"set logical-systems {logical_system} security address-book {zone_name} address {address_name} description {comment}",
                                    f"set logical-systems {logical_system} security address-book {zone_name} address-set {grp_name} address {address_name}"]
                        output = juniper_junos.send_config_set(
                            commands, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                        # Check last command worked or not!
                        addr_group_check_result = juniper_junos.send_config_set(
                            addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                        if address_name in addr_group_check_result:
                            print(
                                f" Object created and added to group: {grp_name}")
                            count += 1
                            changed = True
            if changed:
                output = juniper_junos.commit(comment="Add object by script")
                if "commit complete" in output:
                    print("\n>>> commit complete")
                else:
                    print(output)
            print(
                f"                                                      {count} Object added!")
            juniper_junos.disconnect()
        # ScreenOS ------------------------------------------------------------------
        elif host["device_type"] == "juniper_screenos":
            print(f">>> Looking in {host['host']} juniper_screenos...")
            juniper_screenos = ConnectHandler(**host)
            changed = False
            count = 0
            # Check existense of security zone
            zone_check = f"get zone {zone_name}"
            get_all_zone = "get zone"
            zone_check_result = juniper_screenos.send_command(
                zone_check, expect_string=r">", read_timeout=20)
            # print(zone_check_result)
            while f"Zone name: {zone_name}" not in zone_check_result:
                print(" Zone name not found!")
                get_all_zone_result = juniper_screenos.send_command(
                    get_all_zone, expect_string=r">", read_timeout=20)
                print(get_all_zone_result)
                zone_name = str(input(" Enter correct zone: "))
                zone_check_result = juniper_screenos.send_command(
                    f"get zone {zone_name}", expect_string=r">", read_timeout=20)
            print(f" Zone name: {zone_name}")
            # First check if group name is correct or exist
            group_check = f'get group address {zone_name} {grp_name}'
            group_check_result = juniper_screenos.send_command(
                group_check, expect_string=r">", read_timeout=20)
            create_grp = "n"
            if "Cannot find group" in group_check_result:
                print(f" ERROR! >>> Group: {grp_name} not exist!")
                create_grp_c = input(" \n Do you want to create it? (y/n) ")
                # check input
                if re.match("[Y,y,n,N]", create_grp):
                    create_grp = create_grp_c
                else:
                    print(" Wrong answer!")
            if f"Group Name: {grp_name}" in group_check_result or create_grp == "y":
                for ip_with_mask in ip_list_validated:
                    address_name = convention+ip_with_mask
                    print(" ------- Object:", address_name)
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
                        print("Duplicate group member")
                    elif "Not found" in add_to_group_result:
                        # create address and add to group
                        commands = f"set address {zone_name} {address_name} {ip_with_mask} {comment}"
                        output = juniper_screenos.send_command_timing(commands)
                        commands = f"set group address {zone_name} {grp_name} add {address_name}"
                        output = juniper_screenos.send_command_timing(commands)
                        final_address_check_result = juniper_screenos.send_command(
                            address_check, expect_string=r">")
                        final_group_check_result = juniper_screenos.send_command(
                            addr_group_check, expect_string=r">")
                        if final_group_check_result and final_address_check_result:
                            print(
                                f" Object created and added to group: {grp_name}")
                            count += 1
                            changed = True
                    elif add_to_group_result:
                        print(add_to_group_result)
                    else:
                        print(f" Object added to group: {grp_name}")
                        count += 1
                        changed = True
            if changed:
                output = juniper_screenos.save_config()
                print(output)
            print(
                f"                                                      {count} Object added!")
            juniper_screenos.disconnect()
    except NetmikoTimeoutException:
        print('Connection timed out')
    except NetmikoAuthenticationException:
        print('Authentication failed')


def Remove_via_SSH(host, ip_list_validated, grp_name, convention, logical_system, zone_name):
    print("**************************** Remove via SSH ****************************")
    try:
        if host["device_type"] == "juniper_junos":
            print(f">>> Looking in {host['host']} juniper_junos...")
            juniper_junos = ConnectHandler(**host)
            changed = False
            count = 0
            # Check existense of security zone
            zone_check = f"show configuration logical-systems {logical_system} security zones | match {zone_name}"
            zone_check_result = juniper_junos.send_command(
                zone_check, expect_string=r">", read_timeout=20)
            # print(zone_check_result)
            while f"security-zone {zone_name} " not in zone_check_result:
                if zone_name in zone_check_result:
                    if word_count(zone_name, zone_check_result) > 1:
                        print(zone_check_result)
                        zone_name = str(
                            input(" Multiple zone founded!\n Enter correct zone: "))
                    else:
                        print(zone_check_result)
                        zone_name = str(zone_check_result.split()[1])
                else:
                    print(zone_check_result)
                    print(f" Zone name {zone_name} not found!")
                    zone_name = str(input(" Enter correct zone: "))
                zone_check_result = juniper_junos.send_command(
                    f"show configuration logical-systems {logical_system} security zones | match {zone_name}", expect_string=r">", read_timeout=20)
                print(f" Zone name: {zone_name}")
            # First check if group name is correct or exist
            group_check = f"show configuration logical-systems {logical_system} security address-book {zone_name} | match {grp_name}"
            group_check_result = juniper_junos.send_command(
                group_check, expect_string=r">", read_timeout=20)
            if f"address-set {grp_name}" not in group_check_result:
                print(f" ERROR!!! >>> Group: {grp_name} not exist!")
            else:
                for ip_with_mask in ip_list_validated:
                    address_name = convention+ip_with_mask
                    print(f" ------- Object: {address_name}")
                    # then check address object existence
                    address_check = f"show logical-systems {logical_system} security address-book {zone_name} address {address_name}"
                    # then check address object existence in group
                    addr_group_check = f"show logical-systems {logical_system} security address-book {zone_name} address-set {grp_name} | match {address_name}"
                    # for check if address is last object in group or not!
                    check_last_member = f"show logical-systems {logical_system} security address-book {zone_name} address-set {grp_name}"
                    address_check_result = juniper_junos.send_config_set(
                        address_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    # print(address_check_result)
                    # For junos we use ";" to determine correct input
                    if f"{ip_with_mask};" in address_check_result:
                        addr_group_check_result = juniper_junos.send_config_set(
                            addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                        # print(addr_group_check_result)
                        check_last_member_result = juniper_junos.send_config_set(
                            check_last_member, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                        if "address " + address_name in addr_group_check_result:
                            print(f" Found object in group: {grp_name}")
                            # function to count word 'address' in output of group member check
                            # if count = 1 then we can't continue while group object will be deleted!
                            # print(check_last_member_result)
                            if word_count(";", check_last_member_result) > 1:
                                # delete address from group
                                del_from_group_command = f"delete logical-systems {logical_system} security address-book {zone_name} address-set {grp_name} address {address_name}"
                                # print(del_from_group_command)
                                output = juniper_junos.send_config_set(
                                    del_from_group_command, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                                # print(output)
                                # Check last command worked or not!
                                addr_group_check_result = juniper_junos.send_config_set(
                                    addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                                # print(addr_group_check_result)
                                if "address " + address_name not in addr_group_check_result:
                                    print(
                                        f" Object removed from group: {grp_name}")
                                    count += 1
                                    changed = True
                            else:
                                print(
                                    " ERROR!!! >>> while deleting object! group can't be blank")
                        else:
                            print(f" Object not exist in group: {grp_name}")
                    else:
                        print(f" Object not found!")
                if changed:
                    output = juniper_junos.commit(
                        comment="Removed object by script")
                    if "commit complete" in output:
                        print("\n>>> commit complete")
                    else:
                        print(output)
        # ScreenOS ------------------------------------------------------------------
        elif host["device_type"] == "juniper_screenos":
            print(f">>> Looking in {host['host']} juniper_screenos...")
            juniper_screenos = ConnectHandler(**host)
            changed = False
            count = 0
            # Check existense of security zone
            zone_check = f"get zone {zone_name}"
            get_all_zone = "get zone"
            zone_check_result = juniper_screenos.send_command(
                zone_check, expect_string=r">", read_timeout=20)
            # print(zone_check_result)
            while f"Zone name: {zone_name}" not in zone_check_result:
                print(" Zone name not found!")
                get_all_zone_result = juniper_screenos.send_command(
                    get_all_zone, expect_string=r">", read_timeout=20)
                print(get_all_zone_result)
                zone_name = str(input(" Enter correct zone: "))
                zone_check_result = juniper_screenos.send_command(
                    f"get zone {zone_name}", expect_string=r">", read_timeout=20)
            print(f" Zone name: {zone_name}")
            # First check if group name is correct or exist
            group_check = f'get group address {zone_name} {grp_name}'
            group_check_result = juniper_screenos.send_command(
                group_check, expect_string=r">", read_timeout=20)
            if "Cannot find group" in group_check_result:
                print(f" ERROR!!! >>> Group: {grp_name} not exist!")
            else:
                for ip_with_mask in ip_list_validated:
                    address_name = convention+ip_with_mask
                    print(" -------Object:", address_name)
                    remove_from_group_cmd = f"unset group address {zone_name} {grp_name} remove {address_name}"
                    remove_from_group_result = juniper_screenos.send_command(
                        remove_from_group_cmd, expect_string=r">")
                    if remove_from_group_result:
                        # when we get unknown keyword that means we don't have permision!
                        if "unknown keyword unset" in remove_from_group_result:
                            print(remove_from_group_result)
                            print(" ERROR! >>> Permision denied!")
                        else:
                            # when true returned we have error so print that!
                            print(remove_from_group_result)
                    else:
                        print(f" Object removed from group: {grp_name}")
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


def Config_via_API(host, ip_list_validated, grp_name, convention):
    print("**************************** Add via API ****************************")
    print(">>> Looking in ", host["host"])
    requests.packages.urllib3.disable_warnings()
    count = 0
    try:
        device_ip = host["host"]
        port = host["port"]
        access_token = host["token"]
        headers = {"Authorization": "Bearer " + access_token, }
        url_addrgrp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/"
        response_grp_check = requests.request(
            "GET", url_addrgrp, verify=False, headers=headers)
        # Check existence of Group
        if response_grp_check.status_code == 404:
            print(f" ERROR! >>> Group: {grp_name} not exist!")
        elif response_grp_check.status_code == 200:
            for ip_with_mask in ip_list_validated:
                ip = remove_slash(ip_with_mask)
                ip_mask = ip_with_mask.split('/')[1]
                # print(ip,ip_mask)
                address_name = convention+ip_with_mask
                print("------- Object:", address_name)
                ip_dict = dict()
                # baraye API bejaye slash %2F bayad bzarim
                ip_dict["name"] = address_name
                ip_dict["subnet"] = ip_with_mask
                ip_dict["comment"] = comment
                address_payload = json.dumps(ip_dict)
                # print(address_payload)
                add_member_group_dict = dict()
                add_member_group_dict["name"] = ip_dict["name"]
                group_payload = json.dumps(add_member_group_dict)
                url_address_check = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/{convention}{ip}%2F{ip_mask}/?datasource=1&with_meta=1&"
                url_address = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/"
                url_addr_in_grp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/{convention}{ip}%2F{ip_mask}"

                # Check existence of address in firewall address
                print(" Looking in firewall addresses...")
                response_addr_check = requests.request(
                    "GET", url_address_check, verify=False, headers=headers, data=address_payload)
                if response_addr_check:
                    print(" Object already exist!")
                else:
                    # Create Address
                    print(" Creating address:", ip_dict["name"])
                    response_address = requests.request(
                        "POST", url_address, verify=False, headers=headers, data=address_payload)
                    if response_address.ok:
                        print(" Address created!")
                    else:
                        print(" ERROR!")
                sleep(.3)
                # Check existence of address in group
                print(" Looking in group:", grp_name, "...")
                response_addr_in_group_check = requests.request(
                    "GET", url_addr_in_grp, verify=False, headers=headers)
                # print(response_addr_in_group_check.content)
                if response_addr_in_group_check.status_code == 200:
                    print(
                        f" also in group: {grp_name} \n Nothing changed!")
                elif response_addr_in_group_check.status_code == 404:
                    response_addrgrp = requests.request(
                        "POST", url_addrgrp, verify=False, headers=headers, data=group_payload)
                    # print(response_addrgrp)
                    if response_addrgrp.ok:
                        print(
                            f" Object added to group: {grp_name}")
                        count += 1
                    else:
                        print(" ERROR! >>> adding to group")
                else:
                    print(
                        f" ERROR! >>> Something went wrong!\n{response_addr_in_group_check.status_code}")
        else:
            print(
                f" ERROR! >>> Something went wrong!\n{response_grp_check.status_code}")
        print(
            f"                                                      {count} Object added!")
    except requests.exceptions.RequestException as httpGetError:
        raise SystemExit(httpGetError)


def Remove_via_API(host, ip_list_validated, grp_name, convention):
    print("**************************** Remove via API ****************************")
    print(">>> Looking in ", host["host"])
    requests.packages.urllib3.disable_warnings()
    count = 0
    try:
        device_ip = host["host"]
        port = host["port"]
        access_token = host["token"]
        headers = {"Authorization": "Bearer " + access_token, }
        url_addrgrp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/"
        response_grp_check = requests.request(
            "GET", url_addrgrp, verify=False, headers=headers)
        # Check existence of Group
        if response_grp_check.status_code == 404:
            print(f" ERROR!!! >>> Group: {grp_name} not exist!")
        elif response_grp_check.status_code == 200:
            for ip_with_mask in ip_list_validated:
                ip = remove_slash(ip_with_mask)
                ip_mask = ip_with_mask.split('/')[1]
                # print(ip,ip_mask)
                address_name = convention+ip_with_mask
                print("------- Object:", address_name)
                ip_dict = dict()
                # baraye API bejaye slash %2F bayad bzarim
                ip_dict["name"] = address_name
                ip_dict["subnet"] = ip_with_mask
                address_payload = json.dumps(ip_dict)
                # print(address_payload)
                add_member_group_dict = dict()
                add_member_group_dict["name"] = ip_dict["name"]
                group_payload = json.dumps(add_member_group_dict)
                url_address_check = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/{convention}{ip}%2F{ip_mask}/?datasource=1&with_meta=1&"
                #url_address = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/address/"
                url_addr_in_grp = f"https://{device_ip}:{port}/api/v2/cmdb/firewall/addrgrp/{grp_name}/member/{convention}{ip}%2F{ip_mask}"
                # Check existence of address in firewall address
                print(" Looking in firewall addresses...")
                response_addr_check = requests.request(
                    "GET", url_address_check, verify=False, headers=headers, data=address_payload)
                if response_addr_check.status_code == 200:
                    # Check existence of address in group
                    print(" Looking in group:", grp_name, "...")
                    response_addr_in_group_check = requests.request(
                        "GET", url_addr_in_grp, verify=False, headers=headers)
                    # print(response_addr_in_group_check.content)
                    if response_addr_in_group_check.status_code == 200:
                        response_addrgrp = requests.request(
                            "DELETE", url_addr_in_grp, verify=False, headers=headers, data=group_payload)
                        response_addrgrp_js = response_addrgrp.json()
                        if response_addrgrp.status_code == 200:
                            print(
                                f" object removed from group: {grp_name}")
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
        print(
            f"                                                      {count} Object removed!")
    except requests.exceptions.RequestException as httpGetError:
        raise SystemExit(httpGetError)


if __name__ == "__main__":
    EXIT = "n"
    while EXIT != "y":
        parsed_yaml = read_yaml()
        user_choice = input(
            "\n 1: Add IP to group\n 2: Remove IP from group\nChoose an option:(1|2)")
        print("\n Input file: IP_LIST.txt\n")
        if not re.match("[1,2]", user_choice):
            print("ERROR!!! Only 1 or 2 allowed!")
        else:
            if user_choice == "1":
                print(" Set comment for new objects or leave it blank! |Default: Block-IP|")
                comment = str(input(" Comment: ") or "Block-IP")
                if comment == " ":
                    comment = "-"
            grp_name = str(input("\n |Default: Grp-Blocked-Addresses|\n Enter Group name: ")
                        or "Grp-Blocked-Addresses")  # "testapi"
            zone_name = str(input("\n For Juniper firewalls enter Zone name: "))
            logical_system = str(
                input("\n Enter logical-systems name: "))
            get_convention = str(input("""\n    R for Block IPs\n    A for IP Ranges\n    S for Servers\n    C for Clients\n
            \n |Default: R |\n Select type of objects: """) or "R")
            if not re.match("^[R,A,C,S,r,a,c,s]*$", get_convention):
                print("ERROR!!! Only letters R,A,C,S allowed!")
            else:
                convention = get_convention.capitalize() + ("_")
                with open("IP_LIST.txt", "r") as file:
                    ip_list = file.readlines()
                    ip_list_validated = []
                    for IP_line in ip_list:
                        # remove \n from line
                        ip_with_mask = IP_line.strip("\n")
                        ip_validated = valiadate_ip(ip_with_mask)
                        if ip_validated:
                            ip_list_validated.append(ip_with_mask)
                    print(
                        "----------------------------------\nIP validation has finished process!\n----------------------------------")
                    for host in parsed_yaml["hosts"]:
                        if "juniper" in host["device_type"]:
                            ssh_host_dict = {}
                            # ssh_host_dict.update(login_credentials)
                            ssh_host_dict.update(host)
                            if user_choice == "1":
                                Config_via_SSH(
                                    ssh_host_dict, ip_list_validated, grp_name, logical_system, zone_name)
                            elif user_choice == "2":
                                Remove_via_SSH(ssh_host_dict, ip_list_validated,
                                            grp_name, convention, logical_system, zone_name)
                        elif host["device_type"] == "fortinet":
                            if user_choice == "1":
                                Config_via_API(host, ip_list_validated,
                                            grp_name, convention)
                            elif user_choice == "2":
                                Remove_via_API(host, ip_list_validated,
                                            grp_name, convention)
        EXIT = str(input("\n Finished! Exit?! (y/n) ") or "y")

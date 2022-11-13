import yaml
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from time import sleep
import ipaddress
import requests
import json
import re
# import logging

# logging.basicConfig(filename='netmiko_global.log', level=logging.DEBUG)
# logger = logging.getLogger("netmiko")


def read_yaml(path="Add_Block_IP\inventory.yml"):
    with open(path) as f:
        yaml_content = yaml.safe_load(f.read())
        # print(yaml_content)
    return yaml_content


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


def Config_via_SSH(host, ip_list_validated, grp_name):
    try:
        if host["device_type"] == "juniper_junos":
            print(f">>> Looking in {host['host']} juniper_junos...")
            juniper_junos = ConnectHandler(**host)
            changed = False
            # First check if group name is correct or exist
            group_check = f"show configuration logical-systems  security address-book untrust | match {grp_name}"
            group_check_result = juniper_junos.send_command(
                group_check, expect_string=r">", read_timeout=20)
            if "Cannot find group" in group_check_result:
                print("Cannot find group! it will be created.")
            for ip_with_mask in ip_list_validated:
                print(" IP:", ip_with_mask)
                #ip = remove_slash(ip_with_mask)
                address_name = convention+ip_with_mask
                # then check address object existence
                address_check = f"show logical-systems  security address-book untrust address {address_name}"
                # then check address object existence in group
                addr_group_check = f"show logical-systems  security address-book untrust address-set {grp_name} | match {address_name}"
                address_check_result = juniper_junos.send_config_set(
                    address_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                # print(address_check_result)
                # For junos we use ";" to determine correct input
                if f"{ip_with_mask};" in address_check_result:
                    print(" Object is already exist!")
                    addr_group_check_result = juniper_junos.send_config_set(
                        addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    # print(addr_group_check_result)
                    if "address" + address_name in addr_group_check_result:
                        print(
                            f" also in group: {grp_name}")
                    else:
                        # add address to group
                        add_to_group_command = f"set logical-systems  security address-book untrust address-set {grp_name} address {address_name}"
                        output = juniper_junos.send_config_set(
                            add_to_group_command, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                        # Check last command worked or not!
                        addr_group_check_result = juniper_junos.send_config_set(
                            addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                        if addr_group_check_result:
                            print(f" Just added to group: {grp_name}")
                            changed = True
                else:
                    commands = [f"set logical-systems  security address-book untrust address {address_name} {ip_with_mask}",
                                f"set logical-systems  security address-book untrust address {address_name} description BlockIP",
                                f"set logical-systems  security address-book untrust address-set {grp_name} address {address_name}"]
                    output = juniper_junos.send_config_set(
                        commands, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    # Check last command worked or not!
                    addr_group_check_result = juniper_junos.send_config_set(
                        addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    if addr_group_check_result:
                        print(
                            f" Object created and added to group: {grp_name}")
                        changed = True
            if changed:
                output = juniper_junos.commit(comment="Add Block IP")
                if "commit complete" in output:
                    print("\n>>> commit complete")
                else:
                    print(output)
        # ScreenOS ------------------------------------------------------------------
        elif host["device_type"] == "juniper_screenos":
            print(f">>> Looking in {host['host']} juniper_screenos...")
            juniper_screenos = ConnectHandler(**host)
            changed = False
            # First check if group name is correct or exist
            group_check = f'get group address Untrust {grp_name}'
            group_check_result = juniper_screenos.send_command(
                group_check, expect_string=r">", read_timeout=20)
            if "Cannot find group" in group_check_result:
                print("Cannot find group! it will be created.")
            for ip_with_mask in ip_list_validated:
                print(" IP:", ip_with_mask)
                #ip = remove_slash(ip_with_mask)
                address_name = convention+ip_with_mask
                # check address object existence
                address_check = f'get address Untrust | include {address_name}'
                # then check address object existence in group
                addr_group_check = f'get group address Untrust {grp_name} | include {address_name}'
                address_check_result = juniper_screenos.send_command(
                    address_check, expect_string=r">")
                if ip_with_mask in address_check_result:
                    print(" Object is already exist!")
                    addr_group_check_result = juniper_screenos.send_command(
                        addr_group_check, expect_string=r">")
                    if address_name in addr_group_check_result:
                        print(
                            f" also in group: {grp_name}")
                    else:
                        # add address to group
                        add_to_group_command = f'set group address Untrust {grp_name} add {address_name}'
                        output = juniper_screenos.send_command_timing(
                            add_to_group_command)
                        final_group_check_result = juniper_screenos.send_command_timing(
                            addr_group_check)
                        if final_group_check_result:
                            print(
                                f" Just added to group: {grp_name}")
                            changed = True
                else:
                    commands = f"set address Untrust {address_name} {ip_with_mask} BlockIP"
                    output = juniper_screenos.send_command_timing(commands)
                    commands = f"set group address Untrust {grp_name} add {address_name}"
                    output = juniper_screenos.send_command_timing(commands)
                    final_address_check_result = juniper_screenos.send_command(
                        address_check, expect_string=r">")
                    final_group_check_result = juniper_screenos.send_command(
                        addr_group_check, expect_string=r">")
                    if final_group_check_result and final_address_check_result:
                        print(
                            f" Object created and added to group: {grp_name}")
                        changed = True
            if changed:
                output = juniper_screenos.save_config()
                print(output)

    except NetmikoTimeoutException:
        print('Connection timed out')
    except NetmikoAuthenticationException:
        print('Authentication failed')


def Delete_via_SSH(host, ip_list_validated,grp_name, convention):
    try:
        if host["device_type"] == "juniper_junos":
            print(f">>> Looking in {host['host']} juniper_junos...")
            juniper_junos = ConnectHandler(**host)
            changed = False
            # First check if group name is correct or exist
            group_check = f"show configuration logical-systems  security address-book untrust | match {grp_name}"
            group_check_result = juniper_junos.send_command(
                group_check, expect_string=r">", read_timeout=20)
            if "Cannot find group" in group_check_result:
                print("Cannot find group!")
            else:
                for ip_with_mask in ip_list_validated:
                    print(" IP:", ip_with_mask)
                    #ip = remove_slash(ip_with_mask)
                    address_name = convention+ip_with_mask
                    # then check address object existence
                    address_check = f"show logical-systems  security address-book untrust address {address_name}"
                    # then check address object existence in group
                    addr_group_check = f"show logical-systems  security address-book untrust address-set {grp_name} | match {address_name}"
                    address_check_result = juniper_junos.send_config_set(
                        address_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                    # print(address_check_result)
                    # For junos we use ";" to determine correct input
                    if f"{ip_with_mask};" in address_check_result:
                        print(" Object founded!")
                        addr_group_check_result = juniper_junos.send_config_set(
                            addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                        # print(addr_group_check_result)
                        if "address" + address_name in addr_group_check_result:
                            print(" Found object in group: {grp_name}")
                            # delete address from group
                            add_to_group_command = f"delete logical-systems  security address-book untrust address-set {grp_name} address {address_name}"
                            output = juniper_junos.send_config_set(
                                add_to_group_command, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                            # Check last command worked or not!
                            addr_group_check_result = juniper_junos.send_config_set(
                                addr_group_check, enter_config_mode=True, config_mode_command="configure private", exit_config_mode=False)
                            if address_name not in addr_group_check_result:
                                print(f" Object removed from group: {grp_name}")
                                changed = True
                        else:
                            print(f" Object not exist in group: {grp_name}")
                    else:
                        print(f" Object not found!")
                if changed:
                    output = juniper_junos.commit(comment="Add Block IP")
                    if "commit complete" in output:
                        print("\n>>> commit complete")
                    else:
                        print(output)
        # ScreenOS ------------------------------------------------------------------
        elif host["device_type"] == "juniper_screenos":
            print(f">>> Looking in {host['host']} juniper_screenos...")
            juniper_screenos = ConnectHandler(**host)
            changed = False
            # First check if group name is correct or exist
            group_check = f'get group address Untrust {grp_name}'
            group_check_result = juniper_screenos.send_command(
                group_check, expect_string=r">", read_timeout=20)
            if "Cannot find group" in group_check_result:
                print("Cannot find group! it will be created.")
            for ip_with_mask in ip_list_validated:
                print(" IP:", ip_with_mask)
                #ip = remove_slash(ip_with_mask)
                address_name = convention+ip_with_mask
                # check address object existence
                address_check = f'get address Untrust | include {address_name}'
                # then check address object existence in group
                addr_group_check = f'get group address Untrust {grp_name} | include {address_name}'
                address_check_result = juniper_screenos.send_command(
                    address_check, expect_string=r">")
                if ip_with_mask in address_check_result:
                    print(" Object is already exist!")
                    addr_group_check_result = juniper_screenos.send_command(
                        addr_group_check, expect_string=r">")
                    if address_name in addr_group_check_result:
                        print(
                            f" also in group: {grp_name}")
                    else:
                        # add address to group
                        add_to_group_command = f'set group address Untrust {grp_name} add {address_name}'
                        output = juniper_screenos.send_command_timing(
                            add_to_group_command)
                        final_group_check_result = juniper_screenos.send_command_timing(
                            addr_group_check)
                        if final_group_check_result:
                            print(
                                f" Just added to group: {grp_name}")
                            changed = True
                else:
                    commands = f"set address Untrust {address_name} {ip_with_mask} BlockIP"
                    output = juniper_screenos.send_command_timing(commands)
                    commands = f"set group address Untrust {grp_name} add {address_name}"
                    output = juniper_screenos.send_command_timing(commands)
                    final_address_check_result = juniper_screenos.send_command(
                        address_check, expect_string=r">")
                    final_group_check_result = juniper_screenos.send_command(
                        addr_group_check, expect_string=r">")
                    if final_group_check_result and final_address_check_result:
                        print(
                            f" Object created and added to group: {grp_name}")
                        changed = True
            if changed:
                output = juniper_screenos.save_config()
                print(output)

    except NetmikoTimeoutException:
        print('Connection timed out')
    except NetmikoAuthenticationException:
        print('Authentication failed')


def Config_via_API(host, ip_list_validated, grp_name, convention):
    print("**************************** Fortinet_API ****************************")
    print(">>> Looking in ", host["host"])
    requests.packages.urllib3.disable_warnings()
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
                ip_dict["comment"] = "Blocked_IP"
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
                    print(" Object is already exist!")
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
                            f" Object successfully added to group: {grp_name}")
                    else:
                        print(" Error add to group")
                else:
                    print(
                        f" ERROR! >>> Something went wrong!\n{response_addr_in_group_check.status_code}")
        else:
                print(
                    f" ERROR! >>> Something went wrong!\n{response_grp_check.status_code}")
    except requests.exceptions.RequestException as httpGetError:
        raise SystemExit(httpGetError)


def Delete_via_API(host, ip_list_validated, grp_name, convention):
    print("**************************** Fortinet_API ****************************")
    print(">>> Looking in ", host["host"])
    requests.packages.urllib3.disable_warnings()
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
                #address_name = convention+ip_with_mask
                print("------- Object:", address_name)

                ip_dict = dict()
                # baraye API bejaye slash %2F bayad bzarim
                ip_dict["name"] = address_name
                ip_dict["subnet"] = ip_with_mask
                #ip_dict["comment"] = "Blocked_IP"
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
                                f" object deleted from group: {grp_name}")
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
    except requests.exceptions.RequestException as httpGetError:
        raise SystemExit(httpGetError)


if __name__ == "__main__":
    parsed_yaml = read_yaml()
    #login_credentials = parsed_yaml["vars"]
    #grp_name = "Grp-Blocked-Addresses"
    user_choice = input("To add IPs from the list to the group enter (1)\
        \nTo remove IPs from the group enter (2) >>>: ")
    print("\n Input file: Add_Block_IP\IP_LIST.txt\n")
    grp_name = str(input("\nEnter Group name: "))  # "testapi"
    get_convention = input("""\n    R for Block IPs\n    A for IP Ranges\n    S for Servers\n    C for Clients\n
    Select type of objects: """)
    if not re.match("^[R,A,C,S,r,a,c,s]*$", get_convention):
        print("ERROR!!! Only letters R,A,C,S allowed!")
    else:
        convention = get_convention.capitalize() + ("_")
        with open("Add_Block_IP\IP_LIST.txt", "r") as file:
            ip_list = file.readlines()
            ip_list_validated = []
            for IP_line in ip_list:
                # remove \n from line
                ip_with_mask = IP_line.strip("\n")
                ip_validated = valiadate_ip(ip_with_mask)
                if ip_validated:
                    ip_list_validated.append(ip_with_mask)
            print("----------------------------------\nIP validation has finished process!\n----------------------------------")
            for host in parsed_yaml["hosts"]:
                if "juniper" in host["device_type"]:
                    if user_choice == "1":
                        print(
                            "---------------------------- Add Objects to group ----------------------------")
                        ssh_host_dict = {}
                        # ssh_host_dict.update(login_credentials)
                        ssh_host_dict.update(host)
                        Config_via_SSH(ssh_host_dict, ip_list_validated, grp_name)
                    elif user_choice == "2":
                        print(
                            "---------------------------- Delete Objects from group ----------------------------")
                        #print("fortinet disabled")
                        Delete_via_SSH(ssh_host_dict, ip_list_validated,
                                       grp_name, convention)
                elif host["device_type"] == "fortinet":
                    if user_choice == "1":
                        print(
                            "---------------------------- Add Objects to group ----------------------------")
                        Config_via_API(host, ip_list_validated,
                                       grp_name, convention)
                    elif user_choice == "2":
                        print(
                            "---------------------------- Delete Objects from group ----------------------------")
                        #print("fortinet disabled")
                        Delete_via_API(host, ip_list_validated,
                                       grp_name, convention)


### Done ! agar akharin object to gp srx hazf she gp hazf mishe 

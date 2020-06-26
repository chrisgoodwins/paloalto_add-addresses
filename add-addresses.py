###############################################################################
#
# Script:       add-addresses.py
#
# Author:       Chris Goodwin <chrisgoodwins@gmail.com>
#
# Description:  Create new address objects on a firewall or Panorama device
#               group. The user will also have the option to add the objects
#               to an address group. There are 2 options for adding address
#               objects - either with a comma separated list, or by passing a
#               CSV file via command line argument. The script tests for
#               duplicates within the list provided, as well as on the firewall
#               or device group.
#
# Usage:        add-addresses.py
#               or
#               add-addresses.py <user-provided-list.csv>
#
# Requirements: requests
#
# Python:       Version 3
#
###############################################################################
###############################################################################

import sys
import getpass
import re
import time
from xml.etree import ElementTree as ET
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    raise ValueError('requests support not available, please install module')

###############################################################################
###############################################################################

addrObj_ip, addrObj_fqdn, addrObj_range, allObjNames, addrGroupName = [], [], [], [], None


# Prompts the user to enter an address, then checks it's validity
def getfwipfqdn():
    while True:
        fwipraw = input("\nPlease enter Panorama/firewall IP or FQDN: ")
        ipr = re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", fwipraw)
        fqdnr = re.match(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", fwipraw)
        if ipr:
            break
        elif fqdnr:
            break
        else:
            print("\nThere was something wrong with your entry. Please try again...\n")
    return fwipraw


# Prompts the user to enter a username and password
def getCreds():
    while True:
        username = input("Please enter your user name: ")
        usernamer = re.match(r"^[\w-]{3,24}$", username)
        if usernamer:
            password = getpass.getpass("Please enter your password: ")
            break
        else:
            print("\nThere was something wrong with your entry. Please try again...\n")
    return username, password


# Retrieves the user's api key
def getkey(fwip):
    while True:
        try:
            username, password = getCreds()
            keycall = f"https://{fwip}/api/?type=keygen&user={username}&password={password}"
            r = requests.get(keycall, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') == "success":
                apikey = tree[0][0].text
                break
            else:
                print("\nYou have entered an incorrect username or password. Please try again...\n")
        except requests.exceptions.ConnectionError:
            print("\nThere was a problem connecting to the firewall. Please check the address and try again...\n")
            exit()
    return apikey


# Function to convert a csv file to a list of address object entries
def csvToList(variables_file):
    file = open(variables_file, 'r')
    file_list = []
    for line in file:
        if line != ',\n' and line != '\n':
            line = re.sub(r',?[\r\n]$', '', line)  # Removes comma and/or whitespace at the end of the line
            if line[0] == ',':
                line = re.sub(',', '', line)    # Removes the comma at the beginning of the line when there is no name entry
            else:
                line = re.sub(',', ':', line)   # Replaces the comma with a colon when there is a name entry present
            file_list.append(line)
    return file_list


# Parses address list, checks address validity, and separates object types
def parse_addrList(addrList, argv):
    addrObjCheck_ip = r'^(?:(?:([A-Za-z\d])|(([A-Za-z\d])([\w \.-]){0,61}([\w\.-]))):\s*)?((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)((\/)(3[0-2]|2[0-9]|1[0-9]|[1-9]))?)$'
    addrObjCheck_fqdn = r'^(?:(?:([A-Za-z\d])|(([A-Za-z\d])([\w \.-]){0,61}([\w\.-]))):\s*)?([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    addrObjCheck_range = r'^(?:(?:([A-Za-z\d])|(([A-Za-z\d])([\w \.-]){0,61}([\w\.-]))):\s*)?(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))-(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$'

    addrObj_ip_raw, addrObj_fqdn_raw, addrObj_range_raw, addrObject_errors = [], [], [], []
    for addr in addrList:
        ip_r = re.match(addrObjCheck_ip, addr)
        fqdn_r = re.match(addrObjCheck_fqdn, addr)
        range_r = re.match(addrObjCheck_range, addr)
        if ip_r:
            addrObj_ip_raw.append(addr)
        elif fqdn_r:
            addrObj_fqdn_raw.append(addr)
        elif range_r:
            addrObj_range_raw.append(addr)
        else:
            addrObject_errors.append(addr)
    if addrObject_errors != []:
        time.sleep(.75)
        print('\n')
        for item in addrObject_errors:
            print(f'There was something wrong with your entry -- {item}')
        print('\n\nPalo Alto Networks Naming Convention:\nThe name cannot contain more than 63 characters, and it must start with an alphanumeric character,\nwhile the remainder can contain underscores, hypens, periods, or spaces. Also, the last character cannot be a space.\n\n\nPlease fix the issue, then try again...\n\n')
        if len(argv) > 1:
            exit()
        time.sleep(2)
        return False
    return addrObj_ip_raw, addrObj_fqdn_raw, addrObj_range_raw


# Presents user with instructions and takes user input
def user_input(argv):
    while True:
        if len(argv) < 2:
            user_instructions = '\n\n' + ('*' * 125) + '\n' + ('*' * 125) + "\nThis script will allow you to provide a list of addresses, then create address objects for them (if they don't already exist)\nand add them to an address group (which it will create if it doesn't already exist)\n\nYou can enter info in the following format for any combination of IP/Netmask, FQDN, or IP Range  -- 'name:address'\nThe script will automagically detect what type of address object it is\n\nFor Example -- mailServer:10.42.42.42 or ldapServer:10.42.42.5/32 or dmzNet:10.42.42.0/24\n   or someFQDN:somthing.domain.com or someRange:192.168.42.10-192.168.42.42\n\n...Also, the name is OPTIONAL. If you provide only the address field, the script will automatically name FQDN/Range objects\nthe same as the address, or if it is an IP address, it will name it with the address along with a prefix of 'N-' or 'H-'\n\nLastly, as another option, you can also pass a CSV file as command argument, which would contain the name and address in the\nleft and right columns respectively. There is no need to use the colon-separated format when using this option.\n" + ('*' * 125) + '\n' + ('*' * 125)
            print(user_instructions)
            addrList_string = input('\n\nEnter your comma-separated list of address objects...\n\n')
            addrList = re.sub(r',\s+', ',', addrList_string).split(',')
        else:
            addrList = csvToList(argv[1])
            while True:
                seeList = input("\n\nI see you've entered your list through command argument, would you like to see a printout of the list? [y/N]  ")
                if seeList.lower() == 'y':
                    print('')
                    [print(addr) for addr in addrList]
                    break
                elif seeList.lower() == 'n' or seeList == '':
                    break
                else:
                    time.sleep(.75)
                    print("\n\nThat wasn't an option, please try again with a 'y' or 'n'...")
        rawObjs = parse_addrList(addrList, argv)
        if rawObjs is not False:
            return rawObjs


# Checks for duplicate name values in the list that was provided by the user
def checkListDups():
    global allObjNames
    allObjNames = [obj[0] for obj in addrObj_ip] + [obj[0] for obj in addrObj_fqdn] + [obj[0] for obj in addrObj_range]
    allObjNames_unique = set(allObjNames)
    allObjNames_dup_indices = {value: [i for i, v in enumerate(allObjNames) if v == value] for value in allObjNames_unique}
    name_dup_dict = {}
    name_dupBool = False
    for key in allObjNames_dup_indices:
        if len(allObjNames_dup_indices[key]) > 1:
            name_dup_dict[key] = allObjNames_dup_indices[key]
            name_dupBool = True
    if name_dupBool is True:
        time.sleep(.75)
        print("\nThere are duplicates in the list you provided...\n")
        for key in name_dup_dict:
            print(f'{key} -- used {str(len(name_dup_dict[key]))} times')
        print('\n\nPlease fix the duplicate object issue, the re-run the script\n\n\n')
        exit()


# Builds the address object lists into a more usable format for use in API calls
def addrObjBuilder(addrObj_ip_raw, addrObj_fqdn_raw, addrObj_range_raw):
    global addrObj_ip, addrObj_fqdn, addrObj_range
    for obj in addrObj_ip_raw:
        if ':' in obj:
            addrObj_ip.append(obj.split(':'))  # If the ip object has a name, then split it off
        else:
            if '/' not in obj or '/32' in obj:
                ip_pattern = re.compile(r'^((\d{1,3}\.){3}\d{1,3})')
                ip = ip_pattern.findall(obj)
                addrObj_ip.append([(f'H-{ip[0][0]}'), obj])  # If the ip object has no mask or /32 mask, then make name the same as the address, with a 'H-' prefix
            else:
                mask_pattern = re.compile(r'\d?\d$')
                ip_pattern = re.compile(r'^((\d{1,3}\.){3}\d{1,3})')
                mask = mask_pattern.findall(obj)
                ip = ip_pattern.findall(obj)
                addrObj_ip.append([(f'N-{ip[0][0]}-{mask[0]}'), obj])  # Create the name of the ip object with the 'N-' prefix, address, and -<mask> suffix
    for obj in addrObj_fqdn_raw:
        if ':' in obj:
            addrObj_fqdn.append(obj.split(':'))
        else:
            addrObj_fqdn.append([obj, obj])  # If no name is given for the fqdn object, then the name will be the same as the address
    for obj in addrObj_range_raw:
        if ':' in obj:
            addrObj_range.append(obj.split(':'))
        else:
            addrObj_range.append([f'range_{obj}', obj])  # If no name is given for the range object, then the name will be the same as the address


# Determine whether the device is Panorama or firewall
def getDevType(fwip, mainkey):
    devURL = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/device-group&key={mainkey}"
    r = requests.get(devURL, verify=False)
    devTree = ET.fromstring(r.text)
    if devTree.find('./result/device-group/entry') is None:
        devType = 'fw'
        print('\n\n...Auto-detected device type to be a firewall...\n')
    else:
        devType = 'pano'
        print('\n\n...Auto-detected device type to be Panorama...\n')
    return devType


# Presents the user with a choice of device-groups
def getDG(fwip, mainkey):
    dgXmlUrl = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/device-group&key={mainkey}"
    r = requests.get(dgXmlUrl, verify=False)
    dgfwTree = ET.fromstring(r.text)
    dgList = []
    for entry in dgfwTree.findall('./result/device-group/entry'):
        dgList.append(entry.get('name'))
    dgList.append('Shared')
    while True:
        try:
            print("\n\nHere's a list of device groups found in Panorama...\n")
            for index, dgName in enumerate(dgList):
                print(f'{index + 1}) {dgName}')
            dgChoice = int(input('\nChoose a number for the device-group:\n\nAnswer: '))
            reportDG = dgList[dgChoice - 1]
            break
        except:
            print("\n\nThat's not a number in the list, try again...\n")
            time.sleep(.75)
    return reportDG


# Checks for parent device groups, and returns a list of them
def getParentDGs(fwip, mainkey, panoDG):
    pDGs = []
    dgHierarchyURL = f'https://{fwip}/api/?type=op&cmd=<show><dg-hierarchy></dg-hierarchy></show>&key={mainkey}'
    r = requests.get(dgHierarchyURL, verify=False)
    dgHierarychyTree = ET.fromstring(r.text)
    while True:
        dg = dgHierarychyTree.find(f".//*/[@name='{panoDG}']...")
        if dg.get('name') is None:
            break
        else:
            pDGs.append(dg.get('name'))
            panoDG = dg.get('name')
    return pDGs


# Check for multi-vsys, if so, prompt user to choose vsys number or shared context
def check_vsys(fwip, mainkey):
    multi_vsys_check = f'https://{fwip}/api/?type=op&cmd=<show><system><setting><multi-vsys></multi-vsys></setting></system></show>&key={mainkey}'
    r = requests.get(multi_vsys_check, verify=False)
    tree = ET.fromstring(r.text)
    if tree.find('./result').text == 'off':
        return 'vsys1'
    else:
        print('\n\nLooks like your firewall is running in multi-vsys mode...')
        while True:
            vsys = input('\nEnter the vsys number, or hit leave blank for the shared context: ')
            if vsys == '':
                return 'shared'
            try:
                return f'vsys{str(int(vsys))}'
            except ValueError:
                print("\nThat wasn't a number, try again...\n")


# Checks Panorama device group or firewall for address duplicates
def checkPanDups(fwip, mainkey, panoDG, fw_vsys):
    global addrObj_ip, addrObj_fqdn, addrObj_range
    if panoDG is not None:
        sharedAddrObjURL = f'https://{fwip}/api/?type=config&action=get&xpath=/config/shared/address&key={mainkey}'
        r = requests.get(sharedAddrObjURL, verify=False)
        tree = ET.fromstring(r.text)
        addrObjs = [entry.get('name') for entry in tree.findall('./result/address/entry')]  # Add all addresses from the shared context to the address list ##
        if panoDG != 'Shared':
            allDGs = [panoDG] + getParentDGs(fwip, mainkey, panoDG)
            for dg in allDGs:
                addrObjURL = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/device-group/entry[@name='{dg}']/address&key={mainkey}"
                r = requests.get(addrObjURL, verify=False)
                tree = ET.fromstring(r.text)
                for entry in tree.findall('./result/address/entry'):
                    addrObjs.append(entry.get('name'))  # Add all addresses from the from all parent device groups to the address list ##
    else:
        if fw_vsys == 'shared':
            fwAddrObjURL = f'https://{fwip}/api/?type=config&action=get&xpath=/config/shared/address/address&key={mainkey}'
        else:
            fwAddrObjURL = f"https://{fwip}/api/?type=config&action=get&xpath=/config/devices/entry/vsys/entry[@name='{fw_vsys}']/address&key={mainkey}"
        r = requests.get(fwAddrObjURL, verify=False)
        tree = ET.fromstring(r.text)
        addrObjs = [entry.get('name') for entry in tree.findall('./result/address/entry')]  # Add all addresses from the firewall to the address list ##
    duplicateBool = False
    duplicateList = []
    for obj in allObjNames:  # Loops through the list of all object names to be created ##
        for dev_ojb in addrObjs:  # Loops through the list of all objects that already exist on the Panorama ##
            if obj == dev_ojb:
                duplicateBool = True
                duplicateList.append(obj)
    if duplicateBool is True:
        print(f'\n\nDuplicates were found: {str(len(duplicateList))} of your address objects that you provided already exists on the PAN device...\n')
        print(*duplicateList, sep='\n')
        print('\n\nPlease make note of these addresses, as you will need to make adjustments to the names for these entries,\nthen manually enter them, or re-run this script. These duplicate entries will automatically be removed in order to proceed.\n\n')
        time.sleep(.75)
        for dupObj in duplicateList:
            [addrObj_ip.remove(addrObj) for addrObj in addrObj_ip if dupObj in addrObj]
            [addrObj_fqdn.remove(addrObj) for addrObj in addrObj_fqdn if dupObj in addrObj]
            [addrObj_range.remove(addrObj) for addrObj in addrObj_range if dupObj in addrObj]


# Presents user with option to add an address group
def addGroupOption():
    global addrGroupName
    run = True
    while run:
        addrGroup_answer = input("\n\nOnce the address objects are added, would you like to add them to a group? [Y/n]  ")
        if addrGroup_answer.lower() == 'y' or addrGroup_answer == '':
            while True:
                addrGroupName = input('\nEnter the name the group: ')
                addrGroupName_r = re.match(r'^(?:([A-Za-z\d])|(([A-Za-z\d])([\w \.-]){0,61}([\w\.-])))$', addrGroupName)
                if addrGroupName_r:
                    run = False
                    break
                else:
                    time.sleep(.75)
                    print("\n\nYour address group name does not comply with Palo Alto Networks name convention format\n\nThe name cannot contain more than 63 characters, and it must start with an alphanumeric character,\nwhile the remainder can contain underscores, hypens, periods, or spaces.\nAlso, the last character cannot be a space.\n\nPlease try again...\n")
        elif addrGroup_answer.lower() == 'n':
            print('\nOk, the address objects will be added without a group')
            time.sleep(.75)
            break
        else:
            time.sleep(.75)
            print("\n\nThat wasn't an option, please try again with a 'y' or 'n'...")


# Builds a string of elements to add the xpath in the API call for adding addresses to a group,
# and checks the length of the requests API call to make sure it doesn't go over the 6K character limit, splitting if needed
def addrGroupBuilder(apiCall_piece):
    elements_list = []
    elements_all = f"<entry name='{addrGroupName}'><static>"
    for name in allObjNames:
        if len(elements_all) + len(apiCall_piece) + 23 + len(f'<member>{name}</member>') <= 5000:  # 23 is '</static></entry>' + '-group' in the URL
            elements_all += f'<member>{name}</member>'
        else:
            elements_all += '</static></entry>'
            elements_list.append(elements_all)
            elements_all = f"<entry name='{addrGroupName}'><static><member>{name}</member>"
    elements_all += '</static></entry>'
    elements_list.append(elements_all)
    return elements_list


# Builds a string of elements to add the xpath in the API call for adding addresses to Panorama/FW,
# and checks the length of the requests API call to make sure it doesn't go over the 6K character limit, splitting if needed
def elementBuilder(apiCall_piece):
    elements_list = []
    elements_all = ''
    for obj_ip in addrObj_ip:
        if len(elements_all) + len(apiCall_piece) + len(f"<entry name='{obj_ip[0]}'><ip-netmask>{obj_ip[1]}</ip-netmask></entry>") <= 5000:
            elements_all += f"<entry name='{obj_ip[0]}'><ip-netmask>{obj_ip[1]}</ip-netmask></entry>"
        else:
            elements_list.append(elements_all)
            elements_all = f"<entry name='{obj_ip[0]}'><ip-netmask>{obj_ip[1]}</ip-netmask></entry>"
    for obj_fqdn in addrObj_fqdn:
        if len(elements_all) + len(apiCall_piece) + len(f"<entry name='{obj_fqdn[0]}'><fqdn>{obj_fqdn[1]}</fqdn></entry>") <= 5000:
            elements_all += f"<entry name='{obj_fqdn[0]}'><fqdn>{obj_fqdn[1]}</fqdn></entry>"
        else:
            elements_list.append(elements_all)
            elements_all = f"<entry name='{obj_fqdn[0]}'><fqdn>{obj_fqdn[1]}</fqdn></entry>"
    for obj_range in addrObj_range:
        if len(elements_all) + len(apiCall_piece) + len(f"<entry name='{obj_range[0]}'><ip-range>{obj_range[1]}</ip-range></entry>") <= 5000:
            elements_all += f"<entry name='{obj_range[0]}'><ip-range>{obj_range[1]}</ip-range></entry>"
        else:
            elements_list.append(elements_all)
            elements_all = f"<entry name='{obj_range[0]}'><ip-range>{obj_range[1]}</ip-range></entry>"
    elements_list.append(elements_all)
    return elements_list


# Pushes API calls for address object and group creation
def apiPush(fwip, mainkey, devType, panoDG, fw_vsys):
    print('\n\nTime to push the address objects...')
    time.sleep(.75)
    if devType == 'pano':
        input('\nPress Enter to push API calls to Panorama (or CTRL+C to kill the script)... ')
        if panoDG == 'Shared':
            apiCall_piece = f"https://{fwip}/api/?type=config&action=set&xpath=/config/shared/address&element=&key={mainkey}"
            addrApiCall_part = f"https://{fwip}/api/?type=config&action=set&xpath=/config/shared/address&element="
            addrGroupApiCall_part = f"https://{fwip}/api/?type=config&action=set&xpath=/config/shared/address-group&element="
        else:
            apiCall_piece = f"https://{fwip}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name='{panoDG}']/address&element=&key={mainkey}"
            addrApiCall_part = f"https://{fwip}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name='{panoDG}']/address&element="
            addrGroupApiCall_part = f"https://{fwip}/api/?type=config&action=set&xpath=/config/devices/entry/device-group/entry[@name='{panoDG}']/address-group&element="
        addrObjElements_list = elementBuilder(apiCall_piece)
        if addrGroupName:
            addrGroupElements_list = addrGroupBuilder(apiCall_piece)
    else:
        input('\nPress Enter to push API calls to the firewall (or CTRL+C to kill the script)... ')
        if fw_vsys == 'shared':
            apiCall_piece = f'https://{fwip}/api/?type=config&action=set&xpath=/config/shared/address&element=&key={mainkey}'
            addrApiCall_part = f'https://{fwip}/api/?type=config&action=set&xpath=/config/shared/address&element='
            addrGroupApiCall_part = f'https://{fwip}/api/?type=config&action=set&xpath=/config/shared/address-group&element='
        else:
            apiCall_piece = f"https://{fwip}/api/?type=config&action=set&xpath=/config/devices/entry/vsys/entry[@name='{fw_vsys}']/address&element=&key={mainkey}"
            addrApiCall_part = f"https://{fwip}/api/?type=config&action=set&xpath=/config/devices/entry/vsys/entry[@name='{fw_vsys}']/address&element="
            addrGroupApiCall_part = f"https://{fwip}/api/?type=config&action=set&xpath=/config/devices/entry/vsys/entry[@name='{fw_vsys}']/address-group&element="
        addrObjElements_list = elementBuilder(apiCall_piece)
        if addrGroupName:
            addrGroupElements_list = addrGroupBuilder(apiCall_piece)
    for addrObjElements in addrObjElements_list:
        addrApiCall = f'{addrApiCall_part}{addrObjElements}&key={mainkey}'
        r = requests.get(addrApiCall, verify=False)
        tree = ET.fromstring(r.text)
        if tree.get('status') != 'success':
            time.sleep(.75)
            print(f'\n\nSorry, something went wrong while attempting create your address objects. Below is the faulty API call...\n\n{addrApiCall}\n\n\nTry and fix the issue and give it another shot!\n\nBye for now!\n\n\n')
            exit()
    if addrGroupName:
        time.sleep(.5)
        print(f"\n\n\nCongrats! All your address objects were successfully created\n\n\n\nNow it's time to add the address objects to the {addrGroupName} address group...")
        time.sleep(.5)
        input('\nPress Enter to push API calls to Panorama/firewall (or CTRL+C to kill the script)... ')
        for addrGroupElements in addrGroupElements_list:
            addrGroupApiCall = f'{addrGroupApiCall_part}{addrGroupElements}&key={mainkey}'
            r = requests.get(addrGroupApiCall, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') != 'success':
                time.sleep(.75)
                print(f'\n\nSorry, something went wrong while attempting to add your address objects to the address group. Below is the faulty API call...\n\n{addrGroupApiCall}\n\n\nTry and fix the issue and give it another shot!\n\nBye for now!\n\n\n')
                exit()
            elif addrGroupElements == addrGroupElements_list[-1]:
                time.sleep(.5)
                print(f'\n\n\nCongrats! You successfully added all of your address objects to the {addrGroupName} address group')
    else:
        print('\n\n\nCongrats! You successfully created all of your address objects')


def main():
    global addrObj_ip, addrObj_fqdn, addrObj_range, allObjNames, addrGroupName
    authenticated = False
    while True:

        # If no argument is passed with the command, then the user will be prompted to enter a list of objects
        addrObj_ip_raw, addrObj_fqdn_raw, addrObj_range_raw = user_input(sys.argv)

        # Calls the functions to build the 3 lists with name and address for each element in each list
        addrObjBuilder(addrObj_ip_raw, addrObj_fqdn_raw, addrObj_range_raw)

        # Search the user provided list for duplicates
        checkListDups()

        # Calls the functions to prompt user for Panorama/FW address, and retrieve the API key
        if not authenticated:
            fwip = getfwipfqdn()
            mainkey = getkey(fwip)
            authenticated = True

        # Determine whether the device is Panorama or firewall
        devType = getDevType(fwip, mainkey)

        # If Panorama is the device type, prompt user to choose device group
        panoDG = None
        if devType == 'pano':
            panoDG = getDG(fwip, mainkey)

        # Check to see if firewall is multi-vsys, return vsys number, or shared
        fw_vsys = None
        if devType == 'fw':
            fw_vsys = check_vsys(fwip, mainkey)

        # Check for duplicates between list provided and pano/fw, and remove from list if they exist
        checkPanDups(fwip, mainkey, panoDG, fw_vsys)

        # Option for adding address object group
        addGroupOption()

        # Push API calls
        apiPush(fwip, mainkey, devType, panoDG, fw_vsys)

        # Prompt to run again if CSV was used (the same Pano/FW and credentials will be used)
        if len(sys.argv) == 2:
            while True:
                another_run = input('\n\nWould you like run the script against another CSV file? [Y/n]  ')
                if another_run.lower() == 'y' or another_run == '':
                    sys.argv[1] = input('\nEnter the name of your CSV file: ')
                    addrObj_ip, addrObj_fqdn, addrObj_range, allObjNames, addrGroupName = [], [], [], [], None
                    break
                elif another_run.lower() == 'n':
                    print('\n\n\nHave a fantastic day!!!\n\n\n')
                    exit()
                else:
                    time.sleep(.75)
                    print("\n\nThat wasn't an option, please try again with a 'y' or 'n'...")
        else:
            break
    print('\n\n\nHave a fantastic day!!!\n\n\n')


if __name__ == '__main__':
    main()

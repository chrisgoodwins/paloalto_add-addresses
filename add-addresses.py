###############################################################################
#
# Script:       add-addresses.py
#
# Author:       Chris Goodwin <cgoodwin@paloaltonetworks.com>
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


# Prompts the user to enter the IP/FQDN of a firewall to retrieve the api key
def getfwipfqdn():
    while True:
        try:
            fwipraw = input("Please enter Panorama/firewall IP or FQDN: ")
            ipr = re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", fwipraw)
            fqdnr = re.match(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)", fwipraw)
            if ipr:
                break
            elif fqdnr:
                break
            else:
                print("\nThere was something wrong with your entry. Please try again...\n")
        except:
            print("\nThere was some kind of problem entering your IP or FQDN. Please try again...\n")
    return fwipraw


# Prompts the user to enter their username to retrieve the api key
def getuname():
    while True:
        try:
            username = input("Please enter your user name: ")
            usernamer = re.match(r"^[a-zA-Z0-9_-]{3,24}$", username)  # 3 - 24 characters {3,24}
            if usernamer:
                break
            else:
                print("\nThere was something wrong with your entry. Please try again...\n")
        except:
            print("\nThere was some kind of problem entering your user name. Please try again...\n")
    return username


# Prompts the user to enter their password to retrieve the api key
def getpassword():
    while True:
        try:
            password = getpass.getpass("Please enter your password: ")
            passwordr = re.match(r"^.{5,50}$", password)  # simple validate PANOS has no password characterset restrictions
            if passwordr:
                break
            else:
                print("\nThere was something wrong with your entry. Please try again...\n")
        except:
            print("\nThere was some kind of problem entering your password. Please try again...\n")
    return password


# Retrieves the user's api key
def getkey(fwip):
    while True:
        try:
            fwipgetkey = fwip
            username = getuname()
            password = getpassword()
            keycall = "https://%s/api/?type=keygen&user=%s&password=%s" % (fwipgetkey, username, password)
            r = requests.get(keycall, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') == "success":
                apikey = tree[0][0].text
                break
            else:
                print("\nYou have entered an incorrect username or password. Please try again...\n")
        except requests.exceptions.ConnectionError:
            print("\nThere was a problem connecting to the firewall.  Please check the IP or FQDN and try again...\n")
            exit()
    return apikey


# Builds the address object lists into a more usable format for use in API calls
def addrBuilder(addrObj_ip_raw, addrObj_fqdn_raw, addrObj_range_raw):
    Obj_ip = []
    Obj_fqdn = []
    Obj_range = []
    for obj in addrObj_ip_raw:
        if ':' in obj:
            Obj_ip.append(obj.split(':'))  # If the ip object has a name, then split it off ##
        else:
            if '/' not in obj or '/32' in obj:
                ip_pattern = re.compile('^((\d{1,3}\.){3}\d{1,3})')
                ip = ip_pattern.findall(obj)
                Obj_ip.append([('H-' + ip[0][0]), obj])  # If the ip object has no mask or /32 mask, then make name the same as the address, with a 'H-' prefix ##
            else:
                mask_pattern = re.compile('\d?\d$')
                ip_pattern = re.compile('^((\d{1,3}\.){3}\d{1,3})')
                mask = mask_pattern.findall(obj)
                ip = ip_pattern.findall(obj)
                Obj_ip.append([('N-' + ip[0][0] + '-' + mask[0]), obj])  # Create the name of the ip object with the 'N-' prefix, address, and -<mask> suffix
    for obj in addrObj_fqdn_raw:
        if ':' in obj:
            Obj_fqdn.append(obj.split(':'))
        else:
            Obj_fqdn.append([obj, obj])  # If no name is given for the fqdn object, then the name will be the same as the address ##
    for obj in addrObj_range_raw:
        if ':' in obj:
            Obj_range.append(obj.split(':'))
        else:
            Obj_range.append(['range_' + obj, obj])  # If no name is given for the range object, then the name will be the same as the address ##
    return Obj_ip, Obj_fqdn, Obj_range


# Presents the user with a choice of device-groups
def getDG(fwip, mainkey):
    dgXmlUrl = "https://%s/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group&key=%s" % (fwip, mainkey)
    r = requests.get(dgXmlUrl, verify=False)
    dgfwTree = ET.fromstring(r.text)
    dgList = []
    for entry in dgfwTree.findall('./result/device-group/entry'):
        dgList.append(entry.get('name'))
    while True:
        try:
            print('\n\nHere\'s a list of device groups found in Panorama...\n')
            i = 1
            for dgName in dgList:
                print('%s) %s' % (i, dgName))
                i += 1
            dgChoice = int(input('\nChoose a number for the device-group:\n\nAnswer is: '))
            reportDG = dgList[dgChoice - 1]
            break
        except:
            print("\n\nThat's not a number in the list, try again...\n")
            time.sleep(1)
    return reportDG


# Checks for parent device groups, and returns a list of them
def getParentDGs(fwip, mainkey, panoDG):
    pDGs = []
    dgHierarchyURL = 'https://' + fwip + '/api/?type=op&cmd=<show><dg-hierarchy></dg-hierarchy></show>&key=' + mainkey
    r = requests.get(dgHierarchyURL, verify=False)
    dgHierarychyTree = ET.fromstring(r.text)
    while True:
        dg = dgHierarychyTree.find(".//*/[@name='%s']..." % (panoDG))
        if dg.get('name') is None:
            break
        else:
            pDGs.append(dg.get('name'))
            panoDG = dg.get('name')
    return pDGs


# Checks Panorama device group for address duplicates
def checkDups_pano(fwip, mainkey, allObjNames, panoDG):
    parentDGs = getParentDGs(fwip, mainkey, panoDG)  # Calls function to retrieve all parent device groups ##
    allDGs = [panoDG] + parentDGs
    allDG_addrObjs = []
    sharedAddrObjURL = 'https://' + fwip + "/api/?type=config&action=get&xpath=/config/shared/address&key=" + mainkey
    r = requests.get(sharedAddrObjURL, verify=False)
    tree = ET.fromstring(r.text)
    for entry in tree.findall('./result/address/entry'):
        allDG_addrObjs.append(entry.get('name'))  # Add all addresses from the shared context to the address list ##
    for dg in allDGs:
        addrObjURL = 'https://' + fwip + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" + dg + "']/address&key=" + mainkey
        r = requests.get(addrObjURL, verify=False)
        tree = ET.fromstring(r.text)
        for entry in tree.findall('./result/address/entry'):
            allDG_addrObjs.append(entry.get('name'))  # Add all addresses from the from all parent device groups to the address list ##
    duplicateBool = False
    duplicateList = []
    for obj in allObjNames:  # Loops through the list of all object names to be created ##
        for DG_ojb in allDG_addrObjs:  # Loops through the list of all objects that already exist on the Panorama ##
            if obj == DG_ojb:
                duplicateBool = True
                duplicateList.append(obj)
    return duplicateBool, duplicateList


# Checks firewall for address duplicates
def checkDups_fw(fwip, mainkey, allObjNames):
    fw_addrObjs = []
    fwAddrObjURL = 'https://' + fwip + "/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address&key=" + mainkey
    r = requests.get(fwAddrObjURL, verify=False)
    tree = ET.fromstring(r.text)
    for entry in tree.findall('./result/address/entry'):
        fw_addrObjs.append(entry.get('name'))  # Add all addresses from the firewall to the address list ##
    duplicateBool = False
    duplicateList = []
    for obj in allObjNames:  # Loops through the list of all object names to be created ##
        for fw_ojb in fw_addrObjs:  # Loops through the list of all objects that already exist on the Panorama ##
            if obj == fw_ojb:
                duplicateBool = True
                duplicateList.append(obj)
    return duplicateBool, duplicateList


# Builds a string of elements to add the xpath in the API call for adding addresses to Panorama/FW, and checks the length to make sure it doesn't go over the limit, splitting if needed
def elementBuilder(addrObj_ip, addrObj_fqdn, addrObj_range, apiCall_piece):
    elements_list = []
    elements_all = ''
    for obj_ip in addrObj_ip:
        if len(elements_all) + len(apiCall_piece) + len("<entry name='%s'><ip-netmask>%s</ip-netmask></entry>" % (obj_ip[0], obj_ip[1])) <= 12000:
            elements_all = elements_all + "<entry name='%s'><ip-netmask>%s</ip-netmask></entry>" % (obj_ip[0], obj_ip[1])
        else:
            elements_list.append(elements_all)
            elements_all = "<entry name='%s'><ip-netmask>%s</ip-netmask></entry>" % (obj_ip[0], obj_ip[1])
    for obj_fqdn in addrObj_fqdn:
        if len(elements_all) + len(apiCall_piece) + len("<entry name='%s'><fqdn>%s</fqdn></entry>" % (obj_fqdn[0], obj_fqdn[1])) <= 12000:
            elements_all = elements_all + "<entry name='%s'><fqdn>%s</fqdn></entry>" % (obj_fqdn[0], obj_fqdn[1])
        else:
            elements_list.append(elements_all)
            elements_all = "<entry name='%s'><fqdn>%s</fqdn></entry>" % (obj_fqdn[0], obj_fqdn[1])
    for obj_range in addrObj_range:
        if len(elements_all) + len(apiCall_piece) + len("<entry name='%s'><ip-range>%s</ip-range></entry>" % (obj_range[0], obj_range[1])) <= 12000:
            elements_all = elements_all + "<entry name='%s'><ip-range>%s</ip-range></entry>" % (obj_range[0], obj_range[1])
        else:
            elements_list.append(elements_all)
            elements_all = "<entry name='%s'><ip-range>%s</ip-range></entry>" % (obj_range[0], obj_range[1])
    elements_list.append(elements_all)
    if len(elements_list) > 1:
        input('\n\nYour address object list is too big to push in one API call, so it will be broken into multiple calls\n\nPress Enter to continue (or CTRL+C to kill the script)... ')
    return elements_list


# Function to convert a csv file to a list of address object entries.  Takes in one variable called "variables_file"
def csvToList(variables_file):
    file = open(variables_file, 'r')
    file_list = []
    for line in file:
        line = re.sub('[\r\n]$', '', line)  # Removes whitespace at the end of the line ##
        if line[0] == ',':
            line = re.sub(',', '', line)  # Removes the comma at the beginning of the line when there is no name entry ##
        else:
            line = re.sub(',', ':', line)  # Replaces the comma with a colon when there is a name entry present ##
        file_list.append(line)
    return file_list


def main():
    # If no argument is passed with the command, then the user will be prompted to enter a list of objects
    run = True
    while run:
        if len(sys.argv) < 2:
            print('\n\n*****************************************************************************************************************************\n*****************************************************************************************************************************')
            print("This script will allow you to provide a list of addresses, then create address objects for them (if they don't already exist)\nand add them to an address group (which it will create if it doesn't already exist)\n\nYou can enter info in the following format for any combination of IP/Netmask, FQDN, or IP Range  -- 'name:address'\nThe script will automagically detect what type of address object it is\n\nFor Example -- mailServer:10.42.42.42 or ldapServer:10.42.42.5/32 or dmzNet:10.42.42.0/24\n   or someFQDN:somthing.domain.com or someRange:192.168.42.10-192.168.42.42\n\n...Also, the name is OPTIONAL. If you provide only the address field, the script will automatically name FQDN/Range objects\nthe same as the address, or if it is an IP address, it will name it with the address along with a prefix of 'N-' or 'H-'\n\nLastly, as another option, you can also pass a CSV file as command argument, which would contain the name and address in the\nleft and right columns respectively. There is no need to use the colon-separated format when using this option.")
            print('*****************************************************************************************************************************\n*****************************************************************************************************************************')

            # User input, accepts the list of addresses of multiple types in the format of name:address
            fwList_string = input('\n\nEnter your comma-separated list of address objects...\n\n')
            fwList_string = re.sub(r',\s+', ',', fwList_string)  # Remove any spaces after the commas if they exist ##
            fwList = fwList_string.split(',')  # Splits the string into a list based on commas ##

        else:  # The user can pass a csv file as an argument with the command ##
            # Calls the function to open variable-based csv as a command argument, which iterates over the line and maps values to a list ##
            fwList = csvToList(sys.argv[1])
            while True:
                seeList = input("\n\nI see you've entered your list through command argument, would you like to see a printout of the list? [y/N]  ")
                if seeList == 'Y' or seeList == 'y':
                    print('')
                    for fw in fwList:
                        print(fw)
                    time.sleep(1)
                    break
                elif seeList == 'N' or seeList == 'n' or seeList == '':
                    time.sleep(1)
                    print("\nFair enough, let's get to it...")
                    break
                else:
                    time.sleep(1)
                    print("\n\nThat wasn't an option, please try again with a 'y' or 'n'...")

        # Regex strings for individual name:address entries for each type of address
        addrObjCheck_ip = '^(?:(?:([\w\d])|(([\w\d])([\w\d\._-]))|(([\w\d])([\s\w\d\._-]){1,61}([\w\d\._-]))):\s*)?((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)((\/)(3[0-2]|2[0-9]|1[0-9]|[1-9]))?)$'
        addrObjCheck_fqdn = '^(?:(?:([\w\d])|(([\w\d])([\w\d\._-]))|(([\w\d])([\s\w\d\._-]){1,61}([\w\d\._-]))):\s*)?([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        addrObjCheck_range = '^(?:(?:([\w\d])|(([\w\d])([\w\d\._-]))|(([\w\d])([\s\w\d\._-]){1,61}([\w\d\._-]))):\s*)?(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))-(?:(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$'

        addrObj_ip_raw = []
        addrObj_fqdn_raw = []
        addrObj_range_raw = []

        # Separates the fwList into 3 lists of the differing address types
        for fw in fwList:
            ip_r = re.match(addrObjCheck_ip, fw)
            fqdn_r = re.match(addrObjCheck_fqdn, fw)
            range_r = re.match(addrObjCheck_range, fw)
            if ip_r:
                addrObj_ip_raw.append(fw)
                run = False
            elif fqdn_r:
                addrObj_fqdn_raw.append(fw)
                run = False
            elif range_r:
                addrObj_range_raw.append(fw)
                run = False
            else:
                time.sleep(1)
                print('\n\nThere was something wrong with your entry (%s). Please try again...\n' % (fw))
                if len(sys.argv) >= 2:
                    exit()
                time.sleep(2)
                run = True
                break

    # Calls the functions to build the 3 lists with name and address for each element in each list
    addrObj_ip, addrObj_fqdn, addrObj_range = addrBuilder(addrObj_ip_raw, addrObj_fqdn_raw, addrObj_range_raw)

    # Pulls the names from all 3 lists in order to search the list for duplicates
    allObjNames = []
    for obj in addrObj_ip:
        allObjNames.append(obj[0])
    for obj in addrObj_fqdn:
        allObjNames.append(obj[0])
    for obj in addrObj_range:
        allObjNames.append(obj[0])

    # Checks for duplicate name values in the list that was provided by the user
    allObjNames_unique = set(allObjNames)
    allObjNames_dup_indices = {value: [i for i, v in enumerate(allObjNames) if v == value] for value in allObjNames_unique}
    name_dup_dict = {}
    name_dupBool = False
    for key in allObjNames_dup_indices:
        if len(allObjNames_dup_indices[key]) > 1:
            name_dup_dict[key] = allObjNames_dup_indices[key]
            name_dupBool = True
    if name_dupBool is True:
        time.sleep(1)
        print("\n\n\nThere's at least one duplicate in the list you provided...\n")
        for key in name_dup_dict:
            print(key + ' -- used ' + str(len(name_dup_dict[key])) + ' times')
        print('\n\nPlease fix the duplicate object issue, the re-run the script\n\n\n')
        exit()

    # Calls the functions to prompt user for Panorama/FW address, then retrieves the API key
    print('\n\n')
    fwip = getfwipfqdn()
    mainkey = getkey(fwip)

    # Determines whether the device is Panorama or firewall
    devURL = "https://%s/api/?type=config&action=get&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group&key=%s" % (fwip, mainkey)
    r = requests.get(devURL, verify=False)
    devTree = ET.fromstring(r.text)
    if devTree.find('./result/device-group/entry') is None:
        devType = 'fw'
        print('\n\n...Auto-detected device type to be a firewall...\n')
    else:
        devType = 'pano'
        print('\n\n...Auto-detected device type to be Panorama...\n')

    # If Panorama is the device type, prompt user to choose device group. Then check for duplicates and remove if they exist
    if devType == 'pano':
        panoDG = getDG(fwip, mainkey)  # Calls the function that prompts the user to choose a Panorama device group ##
        dupBool, dupList = checkDups_pano(fwip, mainkey, allObjNames, panoDG)  # Calls the function to check for duplicate address entries ##
        if dupBool is True:
            print('\n\nDuplicates were found: ' + str(len(dupList)) + ' of your addresses that you provided already exists in the ' + panoDG + ' device group...\n')
            for dupAddr in dupList:
                print(dupAddr)
            print('\n\nPlease make note of these addresses, as you will need to make adjustments to the names for these entries,\nthen manually enter them, or re-run this script. These duplicate entries will automatically be removed in order to proceed.\n\n')
    elif devType == 'fw':
        dupBool, dupList = checkDups_fw(fwip, mainkey, allObjNames)  # Calls the function to check for duplicate address entries ##
        if dupBool is True:
            print('\n\nDuplicates were found: ' + str(len(dupList)) + ' of your addresses that you provided already exists on the firewall...\n')
            for dupAddr in dupList:
                print(dupAddr)
            print('\n\nPlease make note of these addresses, as you will need to make adjustments to the names for these entries,\nthen manually enter them, or re-run this script. These duplicate entries will automatically be removed in order to proceed.\n\n')

    # Prompt the user to enter the name of the address group if adding one
    run = True
    while run is True:
        addrGroup_answer = input("\n\nOnce the address objects are added, would you like to add them to a group? [Y/n]  ")
        if addrGroup_answer == 'Y' or addrGroup_answer == 'y' or addrGroup_answer == '':
            while True:
                addrGroupName = input('\nWhat would you like to name the group?  ')
                addrGroupName_r = re.match(r'^([\w\d])|(([\w\d])([\w\d\._-]))$', addrGroupName)
                if addrGroupName_r:
                    # Build the element string for adding address objects to address group
                    addrGroupElements = "<entry name='%s'><static>" % (addrGroupName)
                    for name in allObjNames:
                        addrGroupElements = addrGroupElements + '<member>%s</member>' % (name)
                    addrGroupElements = addrGroupElements + '</static></entry>'
                    run = False
                    break
                else:
                    time.sleep(1)
                    print("\n\nYour address group name does not comply with Palo Alto Networks name convention format, please try again...\n")
        elif addrGroup_answer == 'N' or addrGroup_answer == 'n':
            print('\nOk, the address objects will be added without a group')
            break
        else:
            time.sleep(1)
            print("\n\nThat wasn't an option, please try again with a 'y' or 'n'...")
    time.sleep(1)
    print('\n\nTime to push the address objects...')
    time.sleep(1)
    if devType == 'pano':
        input('\nPress Enter to push API calls to Panorama (or CTRL+C to kill the script)... ')
    else:
        input('\nPress Enter to push API calls to the firewall (or CTRL+C to kill the script)... ')

    # Push API calls to Pano/FW to add address, then add them to address group if desired
    if devType == 'pano':  # If device is Panorama
        apiCall_piece = 'https://' + fwip + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" + panoDG + "']/address&element=" + '&key=' + mainkey
        # Calls the function to build the elements string to add to the API calls
        addrObjElements_list = elementBuilder(addrObj_ip, addrObj_fqdn, addrObj_range, apiCall_piece)
        for addrObjElements in addrObjElements_list:
            addrApiCall_pano = 'https://' + fwip + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" + panoDG + "']/address&element=" + addrObjElements + '&key=' + mainkey
            r = requests.get(addrApiCall_pano, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') == 'success':
                if addrObjElements == addrObjElements_list[-1]:
                    print('\n\n\nCongrats! You successfully added all of your address objects\n')
                    if addrGroup_answer == 'Y' or addrGroup_answer == 'y' or addrGroup_answer == '':
                        time.sleep(1)
                        print("\n\nNow it's time to add the address objects to the %s address group..." % (addrGroupName))
                        time.sleep(1)
                        input('\nPress Enter to push API calls to Panorama/firewall (or CTRL+C to kill the script)... ')
                        addrGroupApiCall_pano = 'https://' + fwip + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" + panoDG + "']/address-group&element=" + addrGroupElements + '&key=' + mainkey
                        r = requests.get(addrGroupApiCall_pano, verify=False)
                        tree = ET.fromstring(r.text)
                        if tree.get('status') == 'success':
                            print('\n\n\nCongrats! You successfully added all of your address objects to the %s address group\n' % (addrGroupName))
                            print('\n\nHave a fantastic day!!!\n\n\n')
                            exit()
                        else:
                            time.sleep(1)
                            print('\n\nSorry, something went wrong while attempting to add your address objects to the address group. Below is the API call which is at fault...\n')
                            print(addrGroupApiCall_pano)
                            print('\n\nTry and fix the issue and give it another shot!\n\nBye for now!\n\n\n')
                            exit()
                    elif addrGroup_answer == 'N' or addrGroup_answer == 'n':
                        print('\nHave a fantastic day!!!\n\n\n')
                        exit()
            else:
                time.sleep(1)
                print('\n\nSorry, something went wrong while attempting to add your address objects. Below is the API call which is at fault...\n')
                print(addrApiCall_pano)
                print('\n\nTry and fix the issue and give it another shot!\n\nBye for now!\n\n\n')
                exit()
    if devType == 'fw':  # If device is firewall
        apiCall_piece = 'https://' + fwip + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address&element=" + '&key=' + mainkey
        # Calls the function to build the elements string to add to the API calls
        addrObjElements_list = elementBuilder(addrObj_ip, addrObj_fqdn, addrObj_range, apiCall_piece)
        for addrObjElements in addrObjElements_list:
            addrApiCall_fw = 'https://' + fwip + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address&element=" + addrObjElements + '&key=' + mainkey
            r = requests.get(addrApiCall_fw, verify=False)
            tree = ET.fromstring(r.text)
            if tree.get('status') == 'success':
                if addrObjElements == addrObjElements_list[-1]:
                    print('\n\n\nCongrats! You successfully added all of your address objects\n')
                    if addrGroup_answer == 'Y' or addrGroup_answer == 'y' or addrGroup_answer == '':
                        time.sleep(1)
                        print("\n\nNow it's time to add the address objects to the %s address group..." % (addrGroupName))
                        time.sleep(1)
                        input('\nPress Enter to push API calls to Panorama/firewall (or CTRL+C to kill the script)... ')
                        addrGroupApiCall_fw = 'https://' + fwip + "/api/?type=config&action=set&xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group&element=" + addrGroupElements + '&key=' + mainkey
                        r = requests.get(addrGroupApiCall_fw, verify=False)
                        tree = ET.fromstring(r.text)
                        if tree.get('status') == 'success':
                            print('\n\n\nCongrats! You successfully added all of your address objects to the %s address group\n' % (addrGroupName))
                            print('\n\nHave a fantastic day!!!\n\n\n')
                            exit()
                        else:
                            time.sleep(1)
                            print('\n\nSorry, something went wrong while attempting to add your address objects to the address group. Below is the API call which is at fault...\n')
                            print(addrGroupApiCall_fw)
                            print('\n\nTry and fix the issue and give it another shot!\n\nBye for now!\n\n\n')
                            exit()
                    elif addrGroup_answer == 'N' or addrGroup_answer == 'n':
                        print('\nHave a fantastic day!!!\n\n\n')
                        exit()
            else:
                time.sleep(1)
                print('\n\nSorry, something went wrong while attempting to add your address objects. Below is the API call which is at fault...\n')
                print(addrApiCall_fw)
                print('\n\nTry and fix the issue and give it another shot!\n\nBye for now!\n\n\n')
                exit()


# CALLS THE MAIN FUNCTION
if __name__ == '__main__':
    main()

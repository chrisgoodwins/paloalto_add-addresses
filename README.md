# paloalto_add-addresses

Simple yet highly flexible script to add address objects in bulk to a Palo Alto Networks firewall or Panorama device group.

## Features

Adderess objects can either be input directly to terminal, or passed in from a CSV file through command line argument

Support for all 3 PAN object types (IP address, FQDN, and IP range), which it will auto-detect

Option to add objects into an object group, which it will create on the fly if it doesn't already exist

The name is also optional. If you provide only the address field, the script will automatically name FQDN/Range objects
the same as the address. If it's an IP address, it will name it with the address along with a prefix of 'H-' for host addresses, or prefix of 'N-', and suffix of '-{mask}' for network addresses.

The script also handles integrety checks for the following:
  * Checks for duplicate objects against firewall/Panorama device group, including objects inherited from device group ancestors
  * Checks for duplicate objects within the list of objects that you provide
  * Checks that the objects conform to PAN standards for input to fields within the address object
  
## How to Use
#### Terminal Input
Enter objects in the following format for any combination of IP/Netmask, FQDN, or IP Range: 'name:address'

For Example -- mailServer:10.42.42.42 or ldapServer:10.42.42.5/32 or dmzNet:10.42.42.0/24
   or someFQDN:somthing.domain.com or someRange:192.168.42.10-192.168.42.42

Objects should be separated by commas when entered into the terminal

#### CSV File Input
You can pass a CSV file as command argument, which would contain the name and address in the
left and right columns respectively. There is no need to use the colon-separated format when using this option.

## TODO
Add support for IP/wildcard-mask address objects, which were introduced in PANOS 9.0

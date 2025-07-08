#!/usr/bin/env python

"""
Script for identifying 'broad' firewall rules which allow 'many' systems to connect to 'many' other systems.
The definition of 'many' is ambiguous, so sane defaults were attempted, but may need to be tweaked for
your environment via `"--broad-ips-count` and `--broad-members-count`.
"""

import argparse
import csv
import ipaddress
import logging
import os

from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.core import xml_object_to_dict
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.pan_helpers import load_API_key


DEFAULT_CONFIG_DIR = os.path.expanduser("~" + os.sep + ".pan_policy_analyzer" + os.sep)
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"

logger = logging.getLogger(__name__)


def get_contained_objects(group_name, all_groups_to_members):
    """Given a the name of an AddressGroup or ServiceGroup, retrieves a set of all the names of objects effectively contained within"""
    contained_members = []
    for member in all_groups_to_members[group_name]:
        if member in all_groups_to_members:
            contained_members += get_contained_objects(member, all_groups_to_members)
        else:
            contained_members += [member]
    return set(contained_members)


def build_group_member_mapping(pan_config, device_group, object_type, xpath):
    """Creates a mapping of AddressGroup or ServiceGroup objects to the underlying objects"""
    # First build the mapping of AddressGroup object names to names of objects contained within:
    all_groups_to_members = {}
    for group_entry in pan_config.get_devicegroup_all_objects(object_type, device_group):
        name = group_entry.get('name')
        members = [member.text for member in group_entry.findall(xpath)]
        all_groups_to_members[name] = members

    # Then build the flattened listing of names to actual objects
    group_to_contained_members = {}
    for group_name in all_groups_to_members:
        group_to_contained_members[group_name] = get_contained_objects(group_name, all_groups_to_members)
    return group_to_contained_members


def get_address_values(pan_config, device_group):
    '''Returns a dictionary of all address objects to their values, which are available to a device group, based on the object hierarchy'''
    # Need to get all addresses up the hierarchy
    device_group_hierarchy_children, device_group_hierarchy_parent = pan_config.get_device_groups_hierarchy()

    all_addresses_dict = {}
    current_dg = device_group
    while current_dg:
        all_addresses = [xml_object_to_dict(i) for i in pan_config.get_devicegroup_object('Addresses', current_dg)]
        for address in all_addresses:
            name = address['entry']['@name']
            if name not in all_addresses_dict:
                all_addresses_dict[name] = address
        current_dg = device_group_hierarchy_parent.get(current_dg)
    return all_addresses_dict


def is_valid_ipv4_address(ipaddr):
    try:
        ipaddress.IPv4Address(ipaddr)
        return True
    except:
        return False


def is_valid_ipv4_network(ipaddr):
    try:
        ipaddress.IPv4Network(ipaddr, strict=False)
        return True
    except:
        return False


def get_member_counts(address_like_members, pan_config, device_group, addressgroups_to_underlying_addresses, all_addresses_dict):
    '''
    This function takes the source/dest Addresses for a firewall policy and determines:
    1) How many unique members there are, based on looking up the contents of each address group
    2) How many total IPs could match this rule.
    '''

    # Let's first short-circuit 'any'
    if address_like_members == ['any']:
        return set(['any']), float('inf')

    edls = [xml_object_to_dict(entry)['entry']['@name'] for entry in pan_config.get_devicegroup_all_objects('ExternalDynamicLists', device_group)]
    regions = [xml_object_to_dict(entry)['entry']['@name'] for entry in pan_config.get_devicegroup_all_objects('Regions', device_group)]

    # If an entry is an Address Groups and flatten those
    members_in_use = set()
    for address_like_member in address_like_members:
        # If it's an AddressGroup, use the entries it contains
        if address_like_member in addressgroups_to_underlying_addresses:
            members_in_use.update(addressgroups_to_underlying_addresses[address_like_member])
        # If it's not an AddressGroup, use the object itself.
        else:
            members_in_use.add(address_like_member)
    # Determine which entries are Address objects and flatten those
    # Now that we've 'flattened' the address groups, we can check how many actual entries are in the
    # source and destination

    num_entries = 0
    for entry in members_in_use:
        if entry in all_addresses_dict:
            addr_object = all_addresses_dict[entry]
            if 'fqdn' in addr_object['entry']:
                num_entries += 1
            elif 'ip-netmask' in addr_object['entry']:
                if '/' not in addr_object['entry']['ip-netmask']:
                    num_entries += 1
                else:
                    netmask = int(addr_object['entry']['ip-netmask'].split('/')[1])
                    num_entries += 2**(32-netmask)
            elif 'ip-range' in addr_object['entry']:
                start, end = addr_object['entry']['ip-range'].split('-')
                num_entries += 1 + (int(ipaddress.IPv4Address(end)) - int(ipaddress.IPv4Address(start)))
            else:
                raise Exception("Unsupported address object type")
        # EDL: Treat as a single entry, since it's intentional
        elif entry in edls:
            num_entries += 1
        # Region: Treat as infinity, since it can be anything
        elif entry in regions:
            num_entries += float('inf')
        # Literal entry
        elif is_valid_ipv4_address(entry):
            num_entries += 1
        elif is_valid_ipv4_network(entry):
            netmask = int(entry.split('/')[1])
            num_entries += 2**(32-netmask)
        else:
            # There are some predefined object types which are referenced, but not defined in the config.
            # We have no choice but to ignore those.
            # raise Exception("Unsupported entry type")
            pass
    return members_in_use, num_entries


def find_broad_rules(pan_config, device_group=None, rules_to_ignore=[], include_postrules=False, broad_members_count=100, broad_ips_count=2**16):
    '''Find broad rules which are incompatible with zero trust'''

    logger.info("*" * 80)
    logger.info("Checking for broad rules, based on size of entries")

    ruletypes = ['SecurityPreRules']
    if include_postrules:
        ruletypes.append('SecurityPostRules')

    # Create a mapping of all address objects to their contents
    if device_group:
        device_groups = [device_group]
    else:
        device_groups = pan_config.get_device_groups()

    # Broad prerules
    broad_prerules = []
    for i, device_group in enumerate(device_groups, start=1):
        logger.info(f"Checking Device group {device_group}")
        # Build the list of all AddressGroups:
        object_type = 'AddressGroups'
        addressgroup_member_xpath = './static/member'
        addressgroups_to_underlying_addresses = build_group_member_mapping(pan_config, device_group, object_type, addressgroup_member_xpath)
        all_addresses_dict = get_address_values(pan_config, device_group)

        for ruletype in ruletypes:
            for rule_num, rule_entry in enumerate(pan_config.get_devicegroup_policy(ruletype, device_group)):
                # Skip disabled rules:
                if rule_entry.find("./disabled") is not None and rule_entry.find("./disabled").text == "yes":
                    continue
                # Skip block and drop rules
                rule_dict = xml_object_to_dict(rule_entry)
                if rule_dict['entry']['action'] != 'allow':
                    continue
                # Skip user ID rules
                if rule_dict['entry']['source-user']['member'] != 'any':
                    continue
                # Skip rules limited to particular URL Categories
                if rule_dict['entry'].get('category', {}).get('member', 'any') != 'any':
                    continue
                # Skip rules intentionally skipped
                if rule_dict['entry']['@name'] in rules_to_ignore:
                    continue

                # The main idea here is to find rules which are 'broad'
                # A rule is defined as 'broad' if both directions have one of the following:
                # a) Address is set to 'Any' or a Region
                # b) /24 or broader subnet entry
                # c) More than 100 unique address objects

                broad_directions = 0
                for direction in ('source', 'destination'):
                    # See if a direction has enough entries to be marked as 'broad':
                    address_members = [elem.text for elem in rule_entry.findall(f'./{direction}/member')]
                    members_in_use, num_entries = get_member_counts(address_members, pan_config, device_group, addressgroups_to_underlying_addresses, all_addresses_dict)
                    if members_in_use == set(['any']):
                        broad_directions += 1
                    elif len(members_in_use) > broad_members_count:
                        broad_directions += 1
                    elif num_entries >= broad_ips_count:
                        broad_directions += 1

                # Both directions
                if broad_directions == 2:
                    broad_rule_entry = {
                        'device_group': device_group,
                        'rule_num': rule_num,
                        'rule_dict': rule_dict['entry']
                    }
                    broad_prerules += [broad_rule_entry]
    return broad_prerules


def find_block_rules(pan_config, device_group=None, include_postrules=False):
    '''Find block/drop rules which could cause a problem with moving rules down'''
    ruletypes = ['SecurityPreRules']
    if include_postrules:
        ruletypes.append('SecurityPostRules')

    # Create a mapping of all address objects to their contents
    if device_group:
        device_groups = [device_group]
    else:
        device_groups = pan_config.get_device_groups()

    # Block rules
    block_rules = []
    for i, device_group in enumerate(device_groups, start=1):
        for ruletype in ruletypes:
            for rule_num, rule_entry in enumerate(pan_config.get_devicegroup_policy(ruletype, device_group)):
                # Skip disabled rules:
                if rule_entry.find("./disabled") is not None and rule_entry.find("./disabled").text == "yes":
                    continue
                # Skip allow rules, since we only care about block and drop rules
                rule_dict = xml_object_to_dict(rule_entry)
                if rule_dict['entry']['action'] == 'allow':
                    continue
                block_rule_entry = {
                    'device_group': device_group,
                    'rule_num': rule_num,
                    'rule_dict': rule_dict['entry']
                }
                block_rules.append(block_rule_entry)
    return block_rules


def listify_entries(entry):
    '''
    An entry can be either a list or a single entry
    Make everything a list to ease operations
    '''
    if type(entry) is list:
        return entry
    else:
        return [entry]


def convert_address_object_dict_to_hosts(addr_dict):
    """
    Takes in a single Address object as a dict and converts
    it into a set of integers representing the underlying hosts.

    If the Address object is dynamic, returns set(['any'])

    Wildcard Addresses not yet supported
    """
    if 'fqdn' in addr_dict['entry']:
        # This can resolve to anything
        return set(['any'])
    elif 'ip-netmask' in addr_dict['entry']:
        # Flattening this to include all hosts is ugly, but not much more we can do
        ip_netmask = addr_dict['entry']['ip-netmask']
        hosts = set([ipaddress.ip_network(ip_netmask, strict=False)])
        return hosts
    elif 'ip-range' in addr_dict['entry']:
        start, end = addr_dict['entry']['ip-range'].split('-')
        start_int = int(ipaddress.IPv4Address(start))
        end_int = int(ipaddress.IPv4Address(end))
        hosts = set()
        for ip_int in range(start=start_int, end=end_int+1):
            hosts.add(ipaddress.ip_network(ip_int, strict=False))
        return hosts
    else:
        raise Exception("Unsupported address object type")


def get_address_underlying_hosts(addresslike_objects, addr_str):
    """
    Takes in a mapping of the firewall's major objects type and a single string for an entry.

    Returns a set of ints representing the IPs in an Address object
    IP Wildcard Mask is not implemented yet
    If an entry is dynamic, it will return 'any' for it.
    """

    # First, get the addr_str's type. Short-circuit for dynamic types:
    if addr_str in addresslike_objects['edls']:
        return set(['any'])

    elif addr_str in addresslike_objects['regions']:
        return set(['any'])

    elif addr_str in addresslike_objects['address']:
        return convert_address_object_dict_to_hosts(addresslike_objects['address'][addr_str])

    elif addr_str in addresslike_objects['addressgroups']:
        # If it's an AddressGroup, decompose it into Address objects,
        # then convert those
        underlying_hosts = set()
        for entry_str in addresslike_objects['addressgroups'][addr_str]:
            addr_dict = addresslike_objects['address'][entry_str]
            underlying_hosts |= convert_address_object_dict_to_hosts(addr_dict)
        return underlying_hosts

    # Check for literal entries:
    elif is_valid_ipv4_address(addr_str):
        return set([ipaddress.ip_network(addr_str, strict=False)])

    elif is_valid_ipv4_network(addr_str):
        return set(ipaddress.ip_network(addr_str, strict=False))

    # Nothing else, so assume it is dynamic:
    return set(['any'])


def networks_have_overlap(networks1, networks2):
    """
    Takes two iterables of IPNetworks and checks if any of them overlap the other`
    """
    for net1 in networks1:
        for net2 in networks2:
            if net1.overlaps(net2):
                return True
    return False


def get_address_like_objects(pan_config, device_group):
    """
    Prepare our data structures of known decompositions:
        a) Address objects to their contents
        b) AddressGroups to their Addresses (TODO: Dynamic AddressGroups as 'any')
        c) EDL names
        d) Region names
    """
    # Build the mapping of all AddressGroups to their underlying Addresses
    object_type = 'AddressGroups'
    addressgroup_member_xpath = './static/member'
    addressgroups_to_underlying_addresses = build_group_member_mapping(pan_config, device_group, object_type, addressgroup_member_xpath)

    # Get the mappings of all Address objects to their contents
    all_addresses_dict = get_address_values(pan_config, device_group)

    edls = [xml_object_to_dict(entry)['entry']['@name'] for entry in pan_config.get_devicegroup_all_objects('ExternalDynamicLists', device_group)]
    regions = [xml_object_to_dict(entry)['entry']['@name'] for entry in pan_config.get_devicegroup_all_objects('Regions', device_group)]

    address_member_types = {
        'address': all_addresses_dict,
        'addressgroups': addressgroups_to_underlying_addresses,
        'edls': edls,
        'regions': regions
    }
    return address_member_types


def rules_overlap(rule, block_rule, addresslike_objects):
    """
    Check if a rule overlaps a block rule
    """
    # Ease of access
    block_dict = block_rule['rule_dict']
    rule_dict = rule['rule_dict']

    # If the source zones don't have any overlap, there can't be a problem:
    rule_dict_src_zones = listify_entries(rule_dict['from']['member'])
    block_dict_src_zones = listify_entries(block_dict['from']['member'])
    if block_dict_src_zones != ['any'] and rule_dict_src_zones != ['any'] and not (set(rule_dict_src_zones) & set(block_dict_src_zones)):
        return False

    # If the dest zones don't have any overlap, there can't be a problem:
    rule_dict_dest_zones = listify_entries(rule_dict['to']['member'])
    block_dict_dest_zones = listify_entries(block_dict['to']['member'])
    if block_dict_dest_zones != ['any'] and rule_dict_dest_zones != ['any'] and not (set(rule_dict_dest_zones) & set(block_dict_dest_zones)):
        return False

    # Check Source addresses for overlapping entries:
    rule_dict_src_networks = set()
    for entry in listify_entries(rule_dict['source']['member']):
        rule_dict_src_networks |= get_address_underlying_hosts(addresslike_objects, entry)

    block_dict_src_networks = set()
    for entry in listify_entries(block_dict['source']['member']):
        block_dict_src_networks |= get_address_underlying_hosts(addresslike_objects, entry)

    if 'any' not in rule_dict_src_networks and 'any' not in block_dict_src_networks and not networks_have_overlap(rule_dict_src_networks, block_dict_src_networks):
        return False

    # Check Dest addresses
    rule_dict_dest_networks = set()
    for entry in listify_entries(rule_dict['destination']['member']):
        rule_dict_dest_networks |= get_address_underlying_hosts(addresslike_objects, entry)

    block_dict_dest_networks = set()
    for entry in listify_entries(block_dict['destination']['member']):
        block_dict_dest_networks |= get_address_underlying_hosts(addresslike_objects, entry)

    if 'any' not in rule_dict_dest_networks and 'any' not in block_dict_dest_networks and not networks_have_overlap(rule_dict_dest_networks, block_dict_dest_networks):
        return False

    # TODO: Check Services
    # TODO: Check App-Ids
    # If we didn't exit, it means that traffic would match both the broad rule and the block rule
    return True


def find_problematic_block_rules(pan_config, device_group, rules, block_rules):
    """For each rule, find all block rules which would cause a problem if the rule was moved to the bottom
    Returns a mapping of rule names to potentially problematic block rules (list)
    """

    # Build a data structure in advance of all of our object types
    addresslike_objects = get_address_like_objects(pan_config, device_group)

    problematic_block_rules = {}
    for rule in rules:
        matching_block_rules = []
        for block_rule in block_rules:
            # Moving the rule down won't make a difference if the
            # block rule is already before the current rule
            if block_rule['rule_num'] < rule['rule_num']:
                continue

            if rules_overlap(rule, block_rule, addresslike_objects):
                matching_block_rules += [block_rule]

        if matching_block_rules:
            rule_name = rule['rule_dict']['@name']
            if rule_name not in problematic_block_rules:
                problematic_block_rules[rule_name] = []
            problematic_block_rules[rule_name] += matching_block_rules
    return problematic_block_rules


def write_broad_prerules(broad_prerules, problematic_block_rules, fname):
    '''Writes rule entries to a file'''
    output = []
    for broad_prerule in broad_prerules:
        row = {}
        row['device_group'] = broad_prerule['device_group']
        row['rule_num'] = broad_prerule['rule_num']
        row['name'] = broad_prerule['rule_dict']['@name']
        row['from'] = broad_prerule['rule_dict']['from']['member']
        row['source'] = broad_prerule['rule_dict']['source']['member']
        row['to'] = broad_prerule['rule_dict']['to']['member']
        row['destination'] = broad_prerule['rule_dict']['destination']['member']
        row['security_profile_group'] = broad_prerule['rule_dict']['profile-setting']['group']['member']
        row['problematic_block_rules'] = ",".join([block_rule['rule_dict']['@name'] for block_rule in problematic_block_rules.get(row['name'], [])])
        output += [row]

    with open(fname, 'w', newline='') as csvfile:
        fieldnames = ['device_group', 'rule_num', 'name', 'from', 'source', 'to', 'destination', 'security_profile_group', 'problematic_block_rules']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output)


def parse_ignore_list(fpath):
    '''Reads the passed in file path and returns a set of rules to ignore as being broad'''
    rules_to_ignore = set()
    with open(fpath) as fh:
        data = fh.read()
        lines = data.split('\n')
        for line in lines:
            line = line.split('#', 1)[0]
            line = line.strip()
            if not line:
                continue
            rules_to_ignore.add(line)
    return rules_to_ignore


def main():
    parser = argparse.ArgumentParser(description="Disable a list of security rules")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--panorama", help="Panorama or Firewall to run on")
    group.add_argument("--xml", help="Process an XML file from 'Export Panorama configuration version'. This does not require an API key")

    parser.add_argument("--device-group", help="Device Group to run on (defaults to running on all device groups)")
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)
    parser.add_argument("--fname", help="Where to store output", default='output.csv')
    parser.add_argument("--ignore-list", help="File with list of rules to ignore")
    parser.add_argument("--broad-ips-count", help="Number of IPs in a rule to be broad", type=int, default=2**16)
    parser.add_argument("--broad-members-count", help="Number of unique members to be broad", type=int, default=100)
    parser.add_argument("--include-postrules", help="Include postrules in analysis", type=bool, default=False)

    parsed_args = parser.parse_args()

    xml = parsed_args.xml
    device_group = parsed_args.device_group
    fname = parsed_args.fname
    broad_members_count = parsed_args.broad_members_count
    broad_ips_count = parsed_args.broad_ips_count
    include_postrules = parsed_args.include_postrules

    # Load XML from either the panorama or a exported configuration
    if parsed_args.panorama:
        panorama = parsed_args.panorama
        api_key = load_API_key(parsed_args.api)
        xml_config = pan_api.export_configuration2(panorama, api_key)
        pan_config = PanConfig(xml_config)
    elif xml:
        with open(xml) as fh:
            xml_config = fh.read()
        pan_config = PanConfig(xml_config, True)

    if parsed_args.ignore_list:
        rules_to_ignore = parse_ignore_list(parsed_args.ignore_list)

    # Find rules which are overly broad
    broad_prerules = find_broad_rules(pan_config, device_group, rules_to_ignore, include_postrules, broad_members_count, broad_ips_count)
    block_rules = find_block_rules(pan_config, device_group, include_postrules)
    problematic_block_rules = find_problematic_block_rules(pan_config, device_group, broad_prerules, block_rules)
    write_broad_prerules(broad_prerules, problematic_block_rules, fname)


if __name__ == '__main__':
    main()

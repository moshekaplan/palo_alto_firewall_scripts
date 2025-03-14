#!/usr/bin/env python

"""
Script for identifying 'broad' firewall rules which allow 'many' systems to connect to 'many' other systems.
The definition of 'many' is ambiguous, so sane defaults were attempted, but may need to be tweaked for
your environment via `"--broad-ips-count` and `--broad-members-count`.
"""

import argparse
import csv
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
            # Include both the Group itself and its contained members
            contained_members += [member]
            contained_members += get_contained_objects(member, all_groups_to_members)
        else:
            contained_members += [member]
    return set(contained_members)


def build_group_member_mapping(pan_config, device_group, object_type, xpath):
    """Creates a mapping of AddressGroup or ServiceGroup objects to the underlying objects"""
    all_groups_to_members = {}
    for group_entry in pan_config.get_devicegroup_all_objects(object_type, device_group):
        name = group_entry.get('name')
        members = [member.text for member in group_entry.findall(xpath)]
        all_groups_to_members[name] = members

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

                # The main idea here is to find rules which are 'very broad'
                # A rule is defined as 'very broad' if it has one of the following
                # in both directions:
                # a) 'Any'
                # b) /24 or broader subnet entry
                # c) More than 100 unique address objects

                broad_directions = 0
                for direction in ('source', 'destination'):
                    # Determine which entries are Address Groups and flatten those
                    address_like_members = [elem.text for elem in rule_entry.findall(f'./{direction}/member')]
                    members_in_use = set()
                    for address_like_member in address_like_members:
                        if address_like_member in addressgroups_to_underlying_addresses:
                            members_in_use.update(addressgroups_to_underlying_addresses[address_like_member])
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
                                import ipaddress
                                num_entries = 1 + (int(ipaddress.IPv4Address(end)) - int(ipaddress.IPv4Address(start)))
                            else:
                                raise Exception("Unsupported address object type")

                    if members_in_use == set(['any']):
                        broad_directions += 1
                    elif len(members_in_use) > broad_members_count:
                        broad_directions += 1
                    elif num_entries >= broad_ips_count:
                        broad_directions += 1

                # Both directions
                if broad_directions == 2:
                    print(rule_dict['entry'])
                    broad_prerules += [[device_group, rule_num, rule_dict['entry']]]

    return broad_prerules


def write_broad_prerules(broad_prerules, fname):
    '''Writes rule entries to a file'''
    output = []
    for device_group, rule_num, entry in broad_prerules:
        row = {}
        row['device_group'] = device_group
        row['rule_num'] = rule_num
        row['name'] = entry['@name']
        row['from'] = entry['from']['member']
        row['source'] = entry['source']['member']
        row['to'] = entry['to']['member']
        row['destination'] = entry['destination']['member']
        row['security_profile_group'] = entry['profile-setting']['group']['member']
        output += [row]

    with open(fname, 'w', newline='') as csvfile:
        fieldnames = ['device_group', 'rule_num', 'name', 'from', 'source', 'to', 'destination', 'security_profile_group']
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
    elif xml:
        with open(xml) as fh:
            xml_config = fh.read()

    if parsed_args.ignore_list:
        rules_to_ignore = parse_ignore_list(parsed_args.ignore_list)

    # Find rules which are overly broad
    pan_config = PanConfig(xml_config)
    broad_prerules = find_broad_rules(pan_config, device_group, rules_to_ignore, include_postrules, broad_members_count, broad_ips_count)
    write_broad_prerules(broad_prerules, fname)


if __name__ == '__main__':
    main()

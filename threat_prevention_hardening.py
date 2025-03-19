#!/usr/bin/env python
"""
Script for assisting with transitioning Threat Prevention to blocking

Steps:
0. Optional: Dump all rules from the Panorama to enable offline review:
a) Create a file with your API key, or be prepared to enter in credentials
b) Run:
python threat_prevention_hardening.py --panorama "panorama.example.com" dump_rules --fpath rules.csv

1. Replace all usage of the original 'default' with a new cloned policy, so that modifying the default Security Profile Group won't change behavior:
a) In Panorama, create a new Security Profile Group by cloning your existing 'default' Security Profile Group. For example, we'll call it 'alert only'.
b) Run:
python threat_prevention_hardening.py --panorama "panorama.example.com" switch_default_usage --group "alert only"

2. Update all rules using an insecure Security Profile Group and no threat hits to use the specified Security Profile Group ("secure" here).
a) Create a file named "insecure_groups.txt" with the list of insecure Security Profile Groups
b) Download your threat logs using a query like the one below
c) Run the Python script as follows:
python threat_prevention_hardening.py --panorama "panorama.example.com" update_no_threat_hits --insecure-groups-fpath insecure_groups.txt --group "secure" --threat-data-fpath "threat_logs.csv"

3. Create a spreadsheet with rule hits and statistics for all rules using an Insecure security Profile Group
a) Create a file named "insecure_groups.txt" with the list of insecure Security Profile Groups (or reuse the file from 2a)
b) Download your threat logs using a query like the one below (same as 2b)
c) Download your traffic logs using a query like the one below
d) Optional: Create a file with a newline-separate list of your development zones, where you have a higher tolerance for failure
e) Run the Python script as follows:
python threat_prevention_hardening.py --panorama "panorama.example.com" prepare_threat_analysis --dev-zones "dev_zones.txt" --insecure-groups-fpath "insecure_groups.txt" --threat-data-fpath "threat_logs.csv" --threat-data-fpath "more_threat_logs.csv" --traffic-data-fpath "rule hits.csv" --fpath "threat_analysis.csv"

4. Update rules using an insecure Security Profile Group and no URL Category hits to use the specified Security Profile Group ("secure" here).
a) Create a file named "insecure_groups.txt" with the list of insecure Security Profile Groups
b) Download your URL Filtering logs using a query like the one below
c) Run the Python script as follows:
python threat_prevention_hardening.py --panorama "panorama.example.com" update_no_threat_hits --insecure-groups-fpath insecure_groups.txt --group "secure" --threat-data-fpath "url_logs.csv"


Note that the Splunk queries below will almost certainly need to be tuned for your environment:

Threat data was collected from Splunk with the following query:

index=* sourcetype="threat" action=allowed subtype IN ("spyware", "virus", "vulnerability") severity IN ("medium", "high", "critical")
| fillnull value=NULL srcuser
| stats count by subtype, rule_uuid, rule, severity, threat_name, threat_id, src_zone, src_ip, src)user, dest_zone, dest_ip, dest_port

Traffic data was collected from Splunk with the following query:

index=* sourcetype="traffic"
| stats count by rule_uuid, rule

URL Filtering data was collected with:

index=* sourcetype="threat" subtype="url" action="allowed" http_category IN ("command-and-control", "compromised-website", "dynamic-dns", "encrypted-dns", "grayware", "malware", "phishing", "ransomware", "scanning-activity")
| fillnull value=NULL src_user
| stats count by rule, rule_uuid, http_category, url, src_zone, src_ip, src_user, dest_zone, dest_ip

File blocking data was collected with:

index=* sourcetype="threat" subtype=file (FileType="Windows Screen Saver SCR File") action=allowed
| fillnull value=NULL src_user
| stats count by rule, rule_uuid, threat_name, src_zone, src_ip, src_user, dest_zone, dest_ip

"""
import argparse
import collections
import csv
import os
import pandas
import duckdb

from palo_alto_firewall_analyzer import pan_api
from palo_alto_firewall_analyzer.core import xml_object_to_dict
from palo_alto_firewall_analyzer.pan_config import PanConfig
from palo_alto_firewall_analyzer.pan_helpers import load_API_key


DEFAULT_CONFIG_DIR = os.path.expanduser("~" + os.sep + ".pan_policy_analyzer" + os.sep)
DEFAULT_API_KEYFILE = DEFAULT_CONFIG_DIR + "API_KEY.txt"


def get_policies(pan_config):
    # Extract the values of interest and flatten the policies into a single list, to ease review
    all_policies = []
    for i, device_group in enumerate(pan_config.get_device_groups()):
        for policy_type in ('SecurityPreRules', 'SecurityPostRules'):
            for policy_entry in pan_config.get_devicegroup_policy(policy_type, device_group):
                rule_name = policy_entry.get('name')
                rule_uuid = policy_entry.get('uuid')
                # It's possible for the 'group' value to be present, but empty, so this returns None
                rule_dict = xml_object_to_dict(policy_entry)['entry']
                group_profile_setting = rule_dict.get('profile-setting', {}).get('group', {})
                if group_profile_setting is None:
                    group_profile_setting = 'default'
                else:
                    group_profile_setting = group_profile_setting.get('member', "")
                policy_row = {'device_group': device_group, 'policy_type': policy_type, 'rule_name': rule_name, 'rule_uuid': rule_uuid, 'group_profile_setting': group_profile_setting, 'rule_dict': rule_dict}
                all_policies += [policy_row]
    return all_policies


def dump_rules(panorama, api_key, fname):
    '''
    Dump all rules and the group profile setting to a CSV file.
    '''
    xml_config = pan_api.export_configuration2(panorama, api_key)
    pan_config = PanConfig(xml_config)

    fw_policies = get_policies(pan_config)

    # Prepare and write our output
    output_data = []
    for fw_policy in fw_policies:
        output_dict = {}
        # First the values we'll just copy over:
        output_dict['device_group'] = fw_policy['device_group']
        output_dict['policy_type'] = fw_policy['policy_type']
        output_dict['rule_name'] = fw_policy['rule_name']
        output_dict['rule_uuid'] = fw_policy['rule_uuid']
        output_dict['group_profile_setting'] = fw_policy['group_profile_setting']
        output_data += [output_dict]

    with open(fname, 'w', newline='') as csvfile:
        fieldnames = ['device_group', 'policy_type', 'rule_name', 'rule_uuid', 'group_profile_setting']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_data)


def switch_default_usage(panorama, api_key, new_profile_group, chunk_amount=None):
    '''
    Update all existing rules using the 'default' Security Profile Group to the
    specified Security Profile Group. This is a first step in having secure defaults.

    If chunk_amount is specified, pause every 'chunk_amount' rules to allow manual
    review and avoid massive commits.
    '''

    xml_config = pan_api.export_configuration2(panorama, api_key)
    pan_config = PanConfig(xml_config)

    # Identify which rules are using the 'default' profile
    fw_policies = get_policies(pan_config)
    default_policies = []
    for policy in fw_policies:
        # Only update those with 'default'
        if policy['group_profile_setting'] == 'default':
            default_policies += [policy]
            print(policy['rule_name'])

    # Update rules using the 'default' profile to use the specified profile
    version = pan_config.get_major_version()
    for i, policy in enumerate(default_policies):
        policy_dict = policy['rule_dict']
        policy_dict['profile-setting'] = {}
        policy_dict['profile-setting']['group'] = {}
        policy_dict['profile-setting']['group']['member'] = new_profile_group
        policy_type = policy['policy_type']
        device_group = policy['device_group']
        pan_api.update_devicegroup_policy(panorama, version, api_key, policy_dict, policy_type, device_group)
        # Pause every 'chunk_amount' rules to enable reveiw and avoid massive commits
        if chunk_amount and i % chunk_amount == 0:
            print("Enter 'c' to continue")
            breakpoint()


def get_fw_policies_no_threat_hits(fw_policies, insecure_groups, threat_data_fname):
    '''
    Determines which firewall rules with insecure policies had no threats.
    '''
    threat_data = pandas.read_csv(threat_data_fname)
    sql = """
    SELECT rule_uuid
    FROM
        threat_data
    """

    result = duckdb.sql(sql).to_df()
    rule_ids_with_threat_hits = set(result.rule_uuid.tolist())
    policies_to_update = []
    for policy in fw_policies:
        # Only update those with less-secure profiles
        if policy['group_profile_setting'] not in insecure_groups:
            continue

        # Skip those which had threat prevention hits
        if policy['rule_uuid'] in rule_ids_with_threat_hits:
            continue

        # Skip block rules:
        if policy['rule_dict']['action'] != 'allow':
            continue

        print(policy['device_group'], policy['rule_name'])
        policies_to_update += [policy]
    return policies_to_update


def update_rules_with_no_threat_hits(panorama, api_key, insecure_groups, new_security_profile_group, threat_data_fpath, chunk_amount=None):
    '''
    Update all rules using an insecure Security Profile Group and no threat hits
    to using the specified Security Profile Group.

    If chunk_amount is specified, pause every 'chunk_amount' rules to allow manual
    review and avoid massive commits.
    '''

    xml_config = pan_api.export_configuration2(panorama, api_key)
    pan_config = PanConfig(xml_config)

    fw_policies = get_policies(pan_config)
    fw_policies_to_update = get_fw_policies_no_threat_hits(fw_policies, insecure_groups, threat_data_fpath)

    # Update default policies to use the new alerting profile
    version = pan_config.get_major_version()

    for i, policy in enumerate(fw_policies_to_update):
        policy_dict = policy['rule_dict']
        policy_dict['profile-setting'] = {}
        policy_dict['profile-setting']['group'] = {}
        policy_dict['profile-setting']['group']['member'] = new_security_profile_group
        policy_type = policy['policy_type']
        device_group = policy['device_group']
        pan_api.update_devicegroup_policy(panorama, version, api_key, policy_dict, policy_type, device_group)
        # Pause every 'chunk_amount' rules to enable reveiw and avoid massive commits
        if chunk_amount and i % chunk_amount == 0:
            print("Enter 'c' to continue")
            breakpoint()


def get_threat_hits_uuids(fnames):
    '''
    Threat data is collected with a Splunk query.
    Returns a mapping of rule UUIDs to threat type to hit count
    '''
    threat_hits = {
        'spyware': collections.Counter(),
        'virus': collections.Counter(),
        'vulnerability': collections.Counter(),
        'total': collections.Counter(),
    }
    for fname in fnames:
        threat_data = pandas.read_csv(fname)
        sql = """
        SELECT rule, rule_uuid, log_subtype, count
        FROM
            threat_data
        """
        result = duckdb.sql(sql).to_df()
        for index, row in result.iterrows():
            threat_hits[row['log_subtype']][row['rule_uuid']] += row['count']
            # May as well calculate this now
            threat_hits['total'][row['rule_uuid']] += row['count']
    return threat_hits


def get_traffic_hits_uuids(fnames):
    '''
    Traffic data is collected with a Splunk query.
    Returns a mapping of rule names to hit count
    '''
    traffic_hits = collections.Counter()
    for fname in fnames:
        traffic_data = pandas.read_csv(fname)
        sql = """
            SELECT rule, rule_uuid, count
        FROM
            traffic_data
        """
        result = duckdb.sql(sql).to_df()
        for index, row in result.iterrows():
            traffic_hits[row['rule_uuid']] += row['count']
    return traffic_hits


def percent_threat_hits(fw_policies, rules_to_threat_hits, rules_to_traffic_hits):
    '''% of connections with threat hits'''
    rules_to_percent_threats = {}
    for fw_policy in fw_policies:
        rule_uuid = fw_policy['rule_uuid']
        threats = rules_to_threat_hits['total'][rule_uuid]
        connections = rules_to_traffic_hits[rule_uuid]

        if connections == 0 and threats == 0:
            percent = 0  # Meaning, no threats
        elif connections == 0 and threats != 0:
            raise Exception(f"No traffic logs, but somehow, threats?! {fw_policy}")
        else:
            percent = 100.0 * threats / connections

        rules_to_percent_threats[rule_uuid] = percent
    return rules_to_percent_threats


def is_dev(dev_zones, fw_policy):
    src_zones = set(fw_policy['rule_dict']['from']['member'])
    dest_zones = set(fw_policy['rule_dict']['to']['member'])
    return ((src_zones <= dev_zones) or (dest_zones <= dev_zones))


def prepare_threat_data_analysis(panorama, api_key, insecure_groups, threat_fnames, traffic_fnames, dev_zones, output_fname):
    '''
    This function creates a CSV listing all of the firewall rules with
    insecure profles that need to be updated, so that a human can review them.

    The spreadsheet will have the following columns:
    column  1  Device group
    column  2: Policy type (pre-rule or post-rule)
    column  3: Policy Name
    column  4: Policy UUID
    column  5: True if all zones involved in at least one side are all development networks
    column  6: Total count of threats allowed (spyware, virus, and vulnerability)
    column  7: Total traffic hits
    column  8: threat hits as a % of total connections
    column  9: Count of allowed spyware threats
    column 10: Count of allowed virus threats
    column 11: Count of allowed vulnerability threats
    column 12: Current assigned Security Profile Group

    When a human reviews it, the reviewer will fill in:
    column 13: Which Security Profile Group to switch to
    column 14: Notes (e.g., rationale, any exceptions needed, etc.)
    '''
    xml_config = pan_api.export_configuration2(panorama, api_key)
    pan_config = PanConfig(xml_config)

    # First get a list of all policies:
    fw_policies = get_policies(pan_config)

    # Limit the list to those rules using an insecure security profile group and so need to be updated:
    fw_policies_insecure = [policy for policy in fw_policies if policy['group_profile_setting'] in insecure_groups]

    # Build a listing of rule_ids to threat hits
    rules_to_threat_hit_uuids = get_threat_hits_uuids(threat_fnames)

    # Build a listing of rule_ids to traffic hits
    rules_to_traffic_hit_uuids = get_traffic_hits_uuids(traffic_fnames)

    # Now start building our data tables:
    # % of connections with threat hits
    rules_to_percent_threats = percent_threat_hits(fw_policies, rules_to_threat_hit_uuids, rules_to_traffic_hit_uuids)

    # Is dev environment:
    rules_to_is_dev = {k['rule_uuid']: is_dev(dev_zones, k) for k in fw_policies_insecure}

    # Prepare and write our output
    output_data = []
    for fw_policy in fw_policies_insecure:
        output_dict = {}
        # First the values we'll just copy over:
        output_dict['device_group'] = fw_policy['device_group']
        output_dict['policy_type'] = fw_policy['policy_type']
        output_dict['rule_name'] = fw_policy['rule_name']
        output_dict['rule_uuid'] = fw_policy['rule_uuid']

        # Next, the values from the other tables:
        rule_uuid = fw_policy['rule_uuid']

        output_dict['is dev'] = rules_to_is_dev[rule_uuid]
        output_dict['threat hits (total)'] = rules_to_threat_hit_uuids['total'][rule_uuid]
        output_dict['traffic hits'] = rules_to_traffic_hit_uuids[rule_uuid]
        output_dict['percent threats'] = rules_to_percent_threats[rule_uuid]

        output_dict['spyware hits'] = rules_to_threat_hit_uuids['spyware'][rule_uuid]
        output_dict['virus hits'] = rules_to_threat_hit_uuids['virus'][rule_uuid]
        output_dict['vuln hits'] = rules_to_threat_hit_uuids['vulnerability'][rule_uuid]

        # For ease of comparison, put this adjacent
        output_dict['group_profile_setting'] = fw_policy['group_profile_setting']
        # And finally, our placeholder values
        output_dict['new_group_profile_setting'] = ''
        output_dict['notes'] = ''
        output_data += [output_dict]

    with open(output_fname, 'w', newline='') as csvfile:
        fieldnames = [
            'device_group', 'policy_type', 'rule_name', 'rule_uuid', 'is dev',
            'threat hits (total)', 'traffic hits', 'percent threats',
            'spyware hits', 'virus hits', 'vuln hits',
            'group_profile_setting',
            'new_group_profile_setting', 'notes']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_data)
    return


def main():
    parser = argparse.ArgumentParser(description="Script for easing transition to using threat prevention in blocking mode")
    parser.add_argument("--panorama", help="Panorama to run on", required=True)
    parser.add_argument("--api", help=f"File with API Key (default is {DEFAULT_API_KEYFILE})", default=DEFAULT_API_KEYFILE)

    # Each command has its own args
    subparsers = parser.add_subparsers(dest='function', required=True)

    # Dump all rules and their group profile setting to a CSV
    parser_dump = subparsers.add_parser('dump_rules', description="test")
    parser_dump.add_argument('--fpath', help="Destination to write CSV of rules to", default='all_rules.csv')

    parser_switch_default_usage = subparsers.add_parser('switch_default_usage', description="Update all rules using the 'default' profile to use a different Security Profile Group, so we can switch to a secure default")
    parser_switch_default_usage.add_argument('--group', help="Group which all rules using the 'default' Security Profile Group should be set to", required=True)
    parser_switch_default_usage.add_argument('--chunk-amount', type=int, help="If specified, break every 'chunk_amount' rules to allow manual review and avoid massive commits")

    parser_update_no_threat_hits = subparsers.add_parser('update_no_threat_hits', description="Update all rules with insecure profiles and no threat hits to use the specified Security Profile Group")
    parser_update_no_threat_hits.add_argument('--insecure-groups-fpath', help="Text file with new-line separated list of insecure Security Profile Groups", required=True)
    parser_update_no_threat_hits.add_argument('--group', help="Group which rules with insecure profiles and no threat hits should be set to", required=True)
    parser_update_no_threat_hits.add_argument('--chunk-amount', type=int, help="If specified, break every 'chunk_amount' rules to allow manual review and avoid massive commits")
    parser_update_no_threat_hits.add_argument('--threat-data-fpath', help="CSV file containing which rules have threats. At minimum, this must have a column for rule_uuid.", required=True)

    parser_prepare_threat_analysis = subparsers.add_parser('prepare_threat_analysis')
    parser_prepare_threat_analysis.add_argument('--dev-zones', help="Text file with new-line separated list of Development zones", required=False, default=list())
    parser_prepare_threat_analysis.add_argument('--insecure-groups-fpath', help="Text file with new-line separated list of insecure Security Profile Groups", required=True)
    parser_prepare_threat_analysis.add_argument('--threat-data-fpath', help="CSV file(s) containing which rules have threats. Can be repeated for multiple files. At minimum, this must have columns for rule, rule_uuid, log_subtype, and count.", action='append', required=True)
    parser_prepare_threat_analysis.add_argument('--traffic-data-fpath', help="CSV file(s) containing which rules have traffic data. Can be repeated for multiple files. At minimum, this must have columns for rule, rule_uuid, and count.", action='append', required=True)
    parser_prepare_threat_analysis.add_argument('--fpath', help="Destination to write CSV of rules to threat stats to", default='threat_analysis.csv')

    parsed_args = parser.parse_args()
    api_key = load_API_key(parsed_args.api)
    panorama = parsed_args.panorama

    if parsed_args.function == 'dump_rules':
        # Dump all rules and their group profile setting to a CSV
        fname = parsed_args.fpath
        print(f"Writing all rules to a CSV file: {fname}")
        dump_rules(panorama, api_key, fname)

    elif parsed_args.function == 'switch_default_usage':
        group = parsed_args.group
        chunk_amount = parsed_args.chunk_amount
        print(f"Updating rules using the 'default' Security Profile Group to instead use '{group}'")
        switch_default_usage(panorama, api_key, group, chunk_amount)

    elif parsed_args.function == 'update_no_threat_hits':
        print("Updating rules with no threat hits")
        with open(parsed_args.insecure_groups_fpath) as fh:
            insecure_groups = fh.read().split('\n')
        new_group = parsed_args.group
        chunk_amount = parsed_args.chunk_amount
        threat_data_fpath = parsed_args.threat_data_fpath
        update_rules_with_no_threat_hits(panorama, api_key, insecure_groups, new_group, threat_data_fpath, chunk_amount)

    elif parsed_args.function == 'prepare_threat_analysis':
        # Prepare a CSV for a human to analyze with a list of rules using an insecure
        # Security Profile Group, their usage, and threat alerts
        with open(parsed_args.insecure_groups_fpath) as fh:
            insecure_groups = fh.read().split('\n')
        threat_data_fpaths = parsed_args.threat_data_fpath
        traffic_data_fpaths = parsed_args.traffic_data_fpath
        with open(parsed_args.dev_zones) as fh:
            dev_zones = set(fh.read().split('\n'))
        output_fpath = parsed_args.fpath
        prepare_threat_data_analysis(panorama, api_key, insecure_groups, threat_data_fpaths, traffic_data_fpaths, dev_zones, output_fpath)


if __name__ == '__main__':
    main()

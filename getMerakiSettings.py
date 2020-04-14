import csv
from datetime import datetime
import re
import meraki
import json

# Uses the Meraki python library (https://github.com/meraki/dashboard-api-python) 
# to create objects containing configuration settings.
# Settings per network are written to csv files for review by a human at a later time.
# The intent is to provide a mechanism to confirm the accuracy of settings across
# networks and prevent drift.

# Note on the API key
# Script uses a key file to inject the Meraki API key. You can also set an
# environment variable 'MERAKI_DASHBOARD_API_KEY' to define your API key as
# well as copy it directly into the script although that is not encouraged.

# Creates the csv header for SSID settings. My use of DictWriter writeheader and writerow methods
# requires I have all possible setting names in my header otherwise I risk errors.
def getSsidHeader(dashboard, networks):
    ssidHeader = []
    # all possible ssid settings
    header = ['name', 'enabled', 'splashPage', 'ssidAdminAccessible', 'adminSplashUrl', 'splashTimeout',
              'walledGardenEnabled','authMode', 'psk', 'encryptionMode', 'wpaEncryptionMode', 'ipAssignmentMode',
              'useVlanTagging', 'defaultVlanId', 'minBitrate', 'bandSelection', 'perClientBandwidthLimitUp',
              'perClientBandwidthLimitDown', 'lanIsolationEnabled', 'availableOnAllAps', 'availabilityTags', 'visible',
              'apTagsAndVlanIds', 'radiusFailoverPolicy', 'radiusAttributeForGroupPolicies', 'radiusOverride',
              'radiusServers', 'radiusAccountingEnabled', 'radiusLoadBalancingPolicy', 'radiusCoaEnabled']
    x = range(1,16)
    # csv writeheader requires unique column names. hack to create those unique names
    # from the list 'header' above by appending a value from range 'x' to the list element.
    for n in x:
        for i in header:
            ssidHeader.append(i + "_" + str(n))
    ssidHeader.insert(0, 'site')
    return (ssidHeader)

def main():
    # Parse API credentials
    key_file_path = 'key_file.txt'
    key_file = open(key_file_path, 'r')
    key_file_text = key_file.read()

    key_file_json = json.loads(key_file_text)
    API_KEY = key_file_json['meraki_api_key']

    # Instantiate a Meraki dashboard API session
    dashboard = meraki.DashboardAPI(api_key=API_KEY, base_url='https://api.meraki.com/api/v0/',
                                   log_file_prefix=__file__[:-3], print_console=False)

    # Get list of organizations
    orgs = dashboard.organizations.getOrganizations()
    # orgs is a list of dict elements, unpack it into a dict of key value pairs
    org_dict = {}
    for org in orgs:
        org_dict.update({org['name']: org['id']})

    # Select Org. Ask for user input, check to see if org exists and if not provide a list of acceptable names.
    while True:
        org_name = input("Enter organization name: ")
        if not org_name in org_dict:
            print("That doesn't seem right. I'm expecting one of the following names.")
            print(*list(org_dict.keys()), sep='\n')
            print("\n")
            continue
        else:
            print("Thank you, one moment please.")
            org_id = org_dict[org_name]
            break

    # Get networks for org
    networks = dashboard.networks.getOrganizationNetworks(org_id)

    # create mx settings doc
    # eventually would like the creation of the file to come after the check in productTypes
    # to prevent empty files.
    with open(f'{org_name}_mx_settings.csv', mode='w', newline='\n') as mx_output:
        # set csv field names, aka column headers
        field_names = ['site', 'productTypes', 'defaultRulesEnabled', 'rules', 'iMode', 'idsRulesets', 'malMode', 'allowedUrls', 'allowedFiles', 'urlCategoryListSize', 'blockedUrlPatterns', 'allowedUrlPatterns', 'blockedUrlCategories']

        # create header row
        writer = csv.DictWriter(mx_output,fieldnames=field_names)
        writer.writeheader()

        # gather data for each network
        for net in networks:
            # check to see if network has an mx appliance
            if 'appliance' in net['productTypes']:
                # prime the dictionary with site and product types
                settings = {'site': net['name'], 'productTypes': net['productTypes']}
                # traffic shaping settings
                settings.update(dashboard.traffic_shaping.getNetworkTrafficShaping(net['id']))

                # intrusion prevention settings
                intrusion_settings = dashboard.intrusion_settings.getNetworkSecurityIntrusionSettings(net['id'])
                # replace key 'mode' with 'iMode' to prevent conflict
                intrusion_settings.update({'iMode': intrusion_settings['mode']})
                del intrusion_settings['mode']
                settings.update(intrusion_settings)

                # malware prevention settings
                malware_settings = dashboard.malware_settings.getNetworkSecurityMalwareSettings(net['id'])
                # replace key 'mode' with 'malMode'
                malware_settings.update({'malMode': malware_settings['mode']})
                del malware_settings['mode']
                settings.update(malware_settings)

                # content filtering settings
                cf = dashboard.content_filtering_rules.getNetworkContentFiltering(net['id'])
                cflist = []

                # cf['blockedUrlCategories'] is list of dict elements. unpack the
                # list, adding the 'name' values to list 'cflist'. 'cflist' becomes
                # new value for key 'blockedUrlCategories'.
                for e in cf['blockedUrlCategories']:
                    cflist.append(e['name'])
                cf.update({'blockedUrlCategories': cflist})
                settings.update(cf)

                writer.writerow(settings)
    mx_output.closed

    # Firewall
    with open(f'{org_name}_fwl_settings.csv', mode='w', newline='\n') as fwl_output:
        field_names2 = ['site', 'productTypes', 'comment', 'policy', 'protocol', 'srcPort', 'srcCidr', 'destPort',
                        'destCidr', 'syslogEnabled']
        writer2 = csv.DictWriter(fwl_output, fieldnames=field_names2)
        writer2.writeheader()

        for net in networks:
            if 'appliance' in net['productTypes']:
                fwsettings = {'site': net['name'], 'productTypes': net['productTypes']}
                # hey look at me including error handling
                try:
                    #assumes only default rule, need to recognize possible multiple fw rules
                    fwsettings.update(dashboard.mx_l3_firewall.getNetworkL3FirewallRules(net['id'])[0])
                except meraki.APIError as e:
                    print(f'Meraki API error: {e}')
                except Exception as e:
                    print(f'some other error: {e}')
                else:
                    writer2.writerow(fwsettings)

    fwl_output.closed

    # SSID settings
    with open(f'{org_name}_ssid_settings.csv', mode='w', newline='\n') as output_ssid:
        # generate header
        fieldnameSsid = getSsidHeader(dashboard, networks)

        writer3 = csv.DictWriter(output_ssid, fieldnames=fieldnameSsid)
        writer3.writeheader()

        for net in networks:
            if 'wireless' in net['productTypes']:
                # settings for 15 SSIDs per site
                ssids = dashboard.ssids.getNetworkSsids(net['id'])
                # prime new dictionary
                ssidSettings = {'site': net['name']}

                for ssid in ssids:
                    # get the value for use later and remove the key/value pair.
                    num = ssid.pop('number')

                    for key in ssid:
                        # match on psk and if key exists
                        if re.match('psk.*', key) is not None and ssid[key] != "":
                            # set unique dict key by appending num + 1
                            # num begins at zero, using num + 1 to match web portal numbering
                            # hide psk value
                            ssidSettings.update({(key + "_" + str(num + 1)): '*****'})
                        else:
                            # for everything not a psk
                            ssidSettings.update({(key + "_" + str(num + 1)): ssid[key]})

                writer3.writerow(ssidSettings)
    output_ssid.closed

if __name__ == '__main__':
    start_time = datetime.now()
    main()
    end_time = datetime.now()
    print(f'\nScript complete, total runtime {end_time - start_time}')

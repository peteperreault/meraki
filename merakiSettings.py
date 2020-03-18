import csv
from datetime import datetime
import re
import meraki

# using the Meraki python library, takes Meraki API Key and Org ID and pulls settings per network, writing them to csv for human review.

# Either input your API key below , or leave API_KEY blank and
# set an environment variable (preferred) to define your API key. The former is insecure and not recommended.
# For example, in Linux/macOS:  export MERAKI_DASHBOARD_API_KEY=093b24e85df15a3e66f1fc359f4c48493eaa1b73
# the key above is used for the Meraki read only sandbox
API_KEY = ''

# the tag organizations.getOrganization() will create a list object with org data. pull the org_id value from the
# 'id' key of the desired org.
# Eventually this will loop thru all orgs or will find the org_id based on org name command line argument.
org_id = ''

def getSsidHeader(dashboard, networks):
    ssidHeader = []
    # all possible ssid settings
    header = ['name', 'enabled', 'splashPage', 'ssidAdminAccessible', 'adminSplashUrl', 'splashTimeout',
              'walledGardenEnabled','authMode', 'psk', 'encryptionMode', 'wpaEncryptionMode', 'ipAssignmentMode',
              'useVlanTagging', 'defaultVlanId', 'minBitrate', 'bandSelection', 'perClientBandwidthLimitUp',
              'perClientBandwidthLimitDown', 'lanIsolationEnabled']
    x = range(1,16)
    # csv writeheader requires unique column names. hack to create those unique names
    # from the list 'header' above by appending a value from range 'x' to the list element.
    for n in x:
        for i in header:
            ssidHeader.append(i + "_" + str(n))
    ssidHeader.insert(0, 'site')
    return (ssidHeader)

def main():
    # Instantiate a Meraki dashboard API session
    dashboard = meraki.DashboardAPI(api_key=API_KEY, base_url='https://api.meraki.com/api/v0/',
                                   log_file_prefix=__file__[:-3], print_console=False)
    networks = dashboard.networks.getOrganizationNetworks(org_id)

    # create mx settings doc
    with open(f'mx_settings.csv', mode='w', newline='\n') as mx_output:
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
    with open(f'fwl_settings.csv', mode='w', newline='\n') as fwl_output:
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
    with open(f'ssid_settings.csv', mode='w', newline='\n') as output_ssid:
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
                    # want the value for use later but not the key/value pair
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

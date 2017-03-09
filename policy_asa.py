"""
Standalone application to convert Tetration Policy to CSV
"""
from apicservice import ConfigDB
import json
import argparse
import csv
import ipcalc


def main():
    """
    Main execution routine
    """
    parser = argparse.ArgumentParser(description='Tetration Policy to CSV')
    parser.add_argument('--maxlogfiles', type=int, default=10, help='Maximum number of log files (default is 10)')
    parser.add_argument('--debug', nargs='?',
                        choices=['verbose', 'warnings', 'critical'],
                        const='critical',
                        help='Enable debug messages.')
    parser.add_argument('--config', default=None, help='Configuration file')
    args = parser.parse_args()

    if args.config is None:
        print '%% No configuration file given'
        return

    # Load in the configuration
    try:
        with open(args.config) as config_file:
            config = json.load(config_file)
    except IOError:
        print '%% Could not load configuration file'
        return
    except ValueError:
        print 'Could not load improperly formatted configuration file'
        return

    # Load in the IANA Protocols
    protocols = {}
    try:
        with open('protocol-numbers-1.csv') as protocol_file:
            reader = csv.DictReader(protocol_file)
            for row in reader:
                protocols[row['Decimal']]=row
    except IOError:
        print '%% Could not load protocols file'
        return
    except ValueError:
        print 'Could not load improperly formatted protocols file'
        return

    # Load in ASA known ports
    ports = {}
    try:
        with open('asa_ports.csv') as protocol_file:
            reader = csv.DictReader(protocol_file)
            for row in reader:
                ports[row['Port']]=row
    except IOError:
        print '%% Could not load protocols file'
        return
    except ValueError:
        print 'Could not load improperly formatted protocols file'
        return

    cdb = ConfigDB()
    cdb.store_config(config)
    clusters = cdb.get_epg_policies()
    policies = cdb.get_contract_policies()

    #Process nodes and output information to CSV
    for cluster in clusters:
        ##Uncomment for ASA Config
        print "object network " + cluster.name.replace(' ','_')
        for node in cluster.get_node_policies():
            ##Uncomment for ASA Config
            node_dict = node.__dict__
            #print node.__dict__['_policy']
            if 'prefix_len' in node_dict['_policy'].keys():
                subnet = ipcalc.Network(node.ip + '/' + str(node_dict['_policy']['prefix_len']))
                print "  subnet " + str(subnet.network()) + ' ' + str(subnet.netmask())
                #print node_dict['_policy']['prefix_len']
            else:
                print "  host " + node.ip

    print '!'

    #Process policies and output information to CSV
    for policy in policies:
        for rule in policy.get_whitelist_policies():

            ##Uncomment for ASA Config
            if policy.src_name == 'External' and policy.dst_name != 'External':
                if rule.proto == '1':
                    #print "access-list ACL_IN extended permit " + protocols[rule.proto]['Keyword'] + " object-group " + policy.src_name.replace(' ','_') + " object-group " + policy.dst_name.replace(' ','_')
                    print "access-list ACL_IN extended permit " + protocols[rule.proto]['Keyword'] + " any object " + policy.dst_name.replace(' ','_')
                elif (rule.proto == '6') or (rule.proto == '17'):
                    if rule.port_min == rule.port_max:
                        if (str(rule.port_min) in ports.keys()) and (ports[str(rule.port_min)]['Proto'] == protocols[rule.proto]['Keyword'] or ports[str(rule.port_min)]['Proto'] == 'TCP, UDP'):
                            port = ports[str(rule.port_min)]['Name']
                        else:
                            port = rule.port_min
                        #print "access-list ACL_IN extended permit " + protocols[rule.proto]['Keyword'] + " object-group " + policy.src_name.replace(' ','_') + " object-group " + policy.dst_name.replace(' ','_') + " eq " + rule.port_min
                        print "access-list ACL_IN extended permit " + protocols[rule.proto]['Keyword'] + " any object " + policy.dst_name.replace(' ','_') + " eq " + port
                    else:
                        #print "access-list ACL_IN extended permit " + protocols[rule.proto]['Keyword'] + " object-group " + policy.src_name.replace(' ','_') + " object-group " + policy.dst_name.replace(' ','_') + " range " + rule.port_min + "-" + rule.port_max
                        print "access-list ACL_IN extended permit " + protocols[rule.proto]['Keyword'] + " any object " + policy.dst_name.replace(' ','_') + " range " + rule.port_min + "-" + rule.port_max



if __name__ == '__main__':
    main()

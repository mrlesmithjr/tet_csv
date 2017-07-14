"""
Standalone application to convert Tetration Policy to CSV
"""
from apicservice import ConfigDB
import json
import argparse
import csv
from TetPolicy2 import Environment

def v2tov1(config):

    external_apps = []
    external_app_ids = []
    for invFilter in config['inventory_filters']:
        external_apps.append(invFilter['name'])
        external_app_ids.append(invFilter['id'])
    #print external_app_ids

    policies = []
    for policy in config['default_policies']:
        if ((policy['consumer_filter_id'] not in external_app_ids) and (policy['provider_filter_id'] not in external_app_ids) and policy['consumer_filter_id'] != policy['provider_filter_id']):
            v1_policy = {}
            v1_policy['src']=policy['consumer_filter_id']
            v1_policy['dst']=policy['provider_filter_id']
            v1_policy['src_name']=policy['consumer_filter_name']
            v1_policy['dst_name']=policy['provider_filter_name']
            v1_policy['whitelist']=[]
            for whitelist in policy['l4_params']:
                whitelist['action']='ALLOW'
                v1_policy['whitelist'].append(whitelist)
            policies.append(v1_policy)
    config['policies']=policies

    clusters = []
    for cluster in config['clusters']:
            v1_cluster = {}
            v1_cluster['name']=cluster['name']
            v1_cluster['id']=cluster['id']
            v1_cluster['external']=cluster['external']
            v1_cluster['nodes']=cluster['nodes']
            v1_cluster['route_tag']={"route_tag": {"subnet_mask": "0.0.0.0/0","name": "N/A"}}
            v1_cluster['labels']=[]
            clusters.append(v1_cluster)

    #print json.dumps(clusters)

    config.pop('clusters',None)
    config['clusters']=clusters
    config['applications']=[]

    config.pop('primary',None)
    config.pop('absolute_policies',None)
    config.pop('catch_all_action',None)
    config.pop('app_scope_id',None)
    config.pop('default_policies',None)
    config.pop('app_scope_id',None)
    config.pop('inventory_filters',None)
    config.pop('created_at',None)
    config.pop('author',None)
    config.pop('description',None)

    return config

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

    # Load in the IANA Ports
    udp = {}
    tcp = {}
    ports = {}
    try:
        with open('service-names-port-numbers.csv') as port_file:
            reader = csv.DictReader(port_file)
            for row in reader:
                if row['Transport Protocol'] == 'tcp':
                    tcp[row['Port Number']] = row
                elif row['Transport Protocol'] == 'udp':
                    udp[row['Port Number']] = row
    except IOError:
        print '%% Could not load protocols file'
        return
    except ValueError:
        print 'Could not load improperly formatted protocols file'
        return
    ports['UDP'] = udp
    ports['TCP'] = tcp

    #Select Tetration Apps and Load Tet Object Model
    tetEnv = Environment()
    tetEnv.loadPolicyFromFile(config=config)
    app = tetEnv.primaryApps[tetEnv.primaryApps.keys()[0]]
    clusters = app.clusters
    filters = app.inventoryFilters
    policies = app.defaultPolicies


    #Process nodes and output information to CSV
    with open(app.name+'-hosts.csv', 'wb') as csvfile:
        nodeswriter = csv.writer(csvfile, delimiter=',',
                                quotechar='|', quoting=csv.QUOTE_MINIMAL)
        nodeswriter.writerow(['Name','IP','Cluster','Application'])
        for key in clusters.keys():
            cluster = clusters[key]
            for host in cluster.hosts:
                nodeswriter.writerow([host['name'],host['ip'],cluster.name,app.name])

    #Process policies and output information to CSV
    with open(app.name+'-policies.csv','wb') as csvfile:
        policywriter = csv.writer(csvfile, delimiter=',',
                                quotechar='|', quoting=csv.QUOTE_MINIMAL)
        policywriter.writerow(['Source Cluster','Destination Cluster','Port Min','Port Max','Protocol','Application'])
        for policy in policies:
            for rule in policy.l4params:
                if ((protocols[str(rule['proto'])]['Keyword'] == 'TCP') or (protocols[str(rule['proto'])]['Keyword'] == 'UDP')) and (rule['port_min'] in ports[protocols[str(rule['proto'])]['Keyword']].keys()):
                    app = ports[protocols[str(rule['proto'])]['Keyword']][rule['port_min']]['Description']
                else:
                    app = ''
                policywriter.writerow([policy.consumerFilterName,policy.providerFilterName,rule['port_min'],rule['port_max'],protocols[str(rule['proto'])]['Keyword'],app])


if __name__ == '__main__':
    main()

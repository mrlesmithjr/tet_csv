"""
Standalone application to convert Tetration Policy to CSV
"""
from apicservice import ConfigDB
import json
import argparse
import csv
import boto3


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

    ec2 = boto3.resource('ec2')
    ec2client = boto3.client('ec2')

    cdb = ConfigDB()
    cdb.store_config(config)
    clusters = cdb.get_epg_policies()
    policies = cdb.get_contract_policies()
    response = ec2client.describe_instances()
    sgs = {}

    existing_groups = ec2client.describe_security_groups()
    sshGroupID = ''
    #Find the ID for the SSH Security Group
    for group in existing_groups["SecurityGroups"]:
        if (group['GroupName'] == 'ssh'):
            sshGroupID = group['GroupId']

    #Process nodes and output information to CSV
    for cluster in clusters:
        print cluster.name
        sg = ec2.create_security_group(GroupName=("group-"+cluster.name.split('(')[0].strip().replace(' ','-')),Description=cluster.name)
        sgs[cluster.name]=sg
        for node in cluster.get_node_policies():
            for instance in response["Reservations"][0]["Instances"]:
                if node.ip == instance['PrivateIpAddress']:
                    print('We have a match! -- ' + instance['InstanceId'])
                    ec2client.modify_instance_attribute(
                    DryRun=False,
                    InstanceId=instance['InstanceId'],
                    Groups=[
                        sg.id,'sg-55b2d129'
                    ])


    #print sgs

    #Process policies and output information to CSV
    for policy in policies:
        for rule in policy.get_whitelist_policies():
            if rule.proto == '1':
                sgs[policy.dst_name].authorize_ingress(IpPermissions=[{'IpProtocol':rule.proto,'UserIdGroupPairs':[{'GroupId':sgs[policy.src_name].id}],'FromPort': -1,'ToPort': -1}])
            elif (rule.proto == '6') or (rule.proto == '17'):
                sgs[policy.dst_name].authorize_ingress(IpPermissions=[{'IpProtocol':rule.proto,'UserIdGroupPairs':[{'GroupId':sgs[policy.src_name].id}],'FromPort': int(rule.port_min),'ToPort': int(rule.port_max)}])




if __name__ == '__main__':
    main()

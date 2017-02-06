import boto3
import json
ec2 = boto3.resource('ec2')
ec2client = boto3.client('ec2')
response = ec2client.describe_security_groups()
response2 = ec2client.describe_instances()
#sg1 = ec2.create_security_group(GroupName="testgroup",Description='testme')
#ec2client.delete_security_group(GroupName="testgroup")
#print json.dumps(response)
for group in response["SecurityGroups"]:
#    for IP
    if (group['GroupName'] != 'default') and (group['GroupName'] != 'ssh'):
        print(group['GroupName'] + " - " + group['GroupId'] +  " - " + str(len(group['IpPermissions'])))
        if len(group['IpPermissions']) > 0:
            response2 = ec2client.revoke_security_group_ingress(
            DryRun=False,
            GroupId=group['GroupId'],
            IpPermissions=group['IpPermissions'])
            #print(response2)

for instance in response2["Reservations"][0]["Instances"]:
    print(instance['InstanceId'] + ' -- ' + instance['PrivateIpAddress'])
    ec2client.modify_instance_attribute(
    DryRun=False,
    InstanceId=instance['InstanceId'],
    Groups=[
        response['SecurityGroups'][0]['GroupId']
    ])

for group in response["SecurityGroups"]:
    if (group['GroupName'] != 'default') and (group['GroupName'] != 'ssh'):
        ec2client.delete_security_group(GroupId=group['GroupId'])

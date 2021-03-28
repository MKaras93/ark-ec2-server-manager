import boto3

import config


def get_ec2_client():
    region = "eu-central-1"
    session = boto3.session.Session(aws_access_key_id=config.KEY_ID,
                                    aws_secret_access_key=config.ACCESS_KEY,
                                    region_name=region)
    ec2 = session.resource("ec2")
    return ec2


def get_security_group(ec2_client, ec2_instance):
    sec_id = ec2_instance.security_groups[0].get("GroupId")
    return ec2_client.SecurityGroup(sec_id)


def clear_sg_rules(security_group):
    print("Clearing security rules.")
    if security_group.ip_permissions:
        print("Revoking rules.")
        return security_group.revoke_ingress(IpPermissions=security_group.ip_permissions)
    else:
        print("No rules to revoke.")


def add_sg_rules(security_group, rules: list):
    print("Adding security rules:")
    print(rules)
    security_group.authorize_ingress(
        DryRun=False,
        IpPermissions=rules
    )


def create_rule(min_port, max_port, protocol, ip_cidr):
    return {
        'FromPort': min_port,
        'ToPort': max_port,
        'IpProtocol': protocol,
        'IpRanges': [
            {
                'CidrIp': ip_cidr,
            },
        ]
    }


def execute_command(instance_id, command):
    print(f"Running command {command} on instance {instance_id}.")
    region = "eu-central-1"
    ssm_client = boto3.client('ssm',
                              region_name=region,
                              aws_access_key_id=config.KEY_ID,
                              aws_secret_access_key=config.ACCESS_KEY,
                              )
    response = ssm_client.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={'commands': [command]}, )

    command_id = response['Command']['CommandId']
    output = ssm_client.get_command_invocation(
        CommandId=command_id,
        InstanceId=instance_id,
    )
    print(output)

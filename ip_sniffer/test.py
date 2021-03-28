from ec2_control import get_ec2_client, get_security_group, create_rule, add_sg_rules, clear_sg_rules
import config

ec2_client = get_ec2_client()
ark_instance = ec2_client.Instance(config.ARK_INSTANCE_ID)
print("starting")
print(ark_instance.stop())
print("security group:")
sec_group = get_security_group(ec2_client, ark_instance)
print(sec_group)
clear_sg_rules(sec_group)

ark_ips = config.PERMANENT_IPS_CIDR
ark_rules = []
for ip_cidr in ark_ips:
    for port_range in config.ARK_PORT_RANGES:
        rule = create_rule(min_port=port_range[0],
                           max_port=port_range[1],
                           protocol=config.ARK_PORT_PROTOCOL,
                           ip_cidr=ip_cidr)
        ark_rules.append(rule)

security_rules = ark_rules
add_sg_rules(sec_group, security_rules)
